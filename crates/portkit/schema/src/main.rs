//! PROTOTYPE CLI for schema grounding.
//!
//!   pks pull <dsn> <out.json> [schemas...]   introspect + materialize
//!   pks show <snapshot>                      what do we know?
//!   pks check <snapshot> <table> [column]    is this name real?

use std::path::Path;
use std::process::ExitCode;

use portkit_schema::{resolve_column, resolve_table, Resolution, Snapshot};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pull") => pull(&args).await,
        Some("show") => show(&args),
        Some("check") => check(&args),
        _ => {
            eprintln!("usage: pks pull|show|check ...");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "postgres"))]
async fn pull(_args: &[String]) -> ExitCode {
    eprintln!("`pks pull` needs live introspection: rebuild with --features postgres");
    eprintln!("(`show` and `check` work from a committed snapshot without it)");
    ExitCode::FAILURE
}

#[cfg(feature = "postgres")]
async fn pull(args: &[String]) -> ExitCode {
    use portkit_schema::capture;
    let (Some(dsn), Some(out)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: pks pull <dsn> <out.json> [schema...]");
        return ExitCode::FAILURE;
    };
    let schemas: Vec<&str> = if args.len() > 3 {
        args[3..].iter().map(String::as_str).collect()
    } else {
        vec!["public"]
    };

    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(dsn)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not connect: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Never record the DSN: provenance travels into agent context and commits.
    let locator = sanitize(dsn);
    let snap = match capture(&pool, &schemas, "fellwork", &locator).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let bytes = match snap.save(Path::new(out)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!("captured {} ({} schemas)", locator, schemas.len());
    println!("  tables       {}", snap.tables.len());
    println!("  columns      {}", snap.column_count());
    println!("  enums        {}", snap.enums.len());
    println!("  functions    {}", snap.functions.len());
    println!("  fingerprint  {}", snap.provenance.fingerprint);
    println!("  snapshot     {bytes} B → {out}");
    ExitCode::SUCCESS
}

fn show(args: &[String]) -> ExitCode {
    let Some(path) = args.get(1) else {
        eprintln!("usage: pks show <snapshot>");
        return ExitCode::FAILURE;
    };
    let Ok(s) = Snapshot::load(Path::new(path)) else {
        eprintln!("could not load {path}");
        return ExitCode::FAILURE;
    };
    println!(
        "source      {} ({:?})",
        s.provenance.source, s.provenance.kind
    );
    println!("locator     {}", s.provenance.locator);
    println!("captured    {}", s.provenance.captured_at);
    println!("fingerprint {}", s.provenance.fingerprint);
    println!(
        "tables      {} ({} columns)",
        s.tables.len(),
        s.column_count()
    );
    ExitCode::SUCCESS
}

fn check(args: &[String]) -> ExitCode {
    let (Some(path), Some(table)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: pks check <snapshot> <table> [column]");
        return ExitCode::FAILURE;
    };
    let Ok(s) = Snapshot::load(Path::new(path)) else {
        eprintln!("could not load {path}");
        return ExitCode::FAILURE;
    };

    let res = match args.get(3) {
        Some(col) => resolve_column(&s, table, col),
        None => resolve_table(&s, table),
    };

    match res {
        Resolution::Known { name } => {
            println!("OK  `{name}` exists");
            if args.get(3).is_none() {
                if let Some(t) = s.table(table) {
                    let cols: Vec<&str> = t.columns.iter().map(|c| c.name.as_str()).collect();
                    println!("    columns: {}", cols.join(", "));
                }
            }
            provenance(&s);
            ExitCode::SUCCESS
        }
        Resolution::Unknown { name, suggestions } => {
            println!("NO  `{name}` does not exist");
            for sg in &suggestions {
                println!("    did you mean `{}`? (distance {})", sg.name, sg.distance);
            }
            if suggestions.is_empty() {
                println!("    no close match");
            }
            provenance(&s);
            ExitCode::FAILURE
        }
    }
}

fn provenance(s: &Snapshot) {
    // Always stamped: a snapshot answer and a live answer can disagree, and
    // the caller has to know which one it got.
    println!(
        "    [{} @ {:?}, captured {}, fingerprint {}]",
        s.provenance.source,
        s.provenance.kind,
        &s.provenance.captured_at[..s.provenance.captured_at.len().min(19)],
        s.provenance.fingerprint
    );
}

/// Strip credentials from a DSN so provenance can be committed safely.
#[cfg(feature = "postgres")]
fn sanitize(dsn: &str) -> String {
    match dsn.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.rsplit('@').next().unwrap_or(rest);
            format!("{scheme}://{host}")
        }
        None => dsn.to_string(),
    }
}
