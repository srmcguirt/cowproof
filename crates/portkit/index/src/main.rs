//! PROTOTYPE: does a resident symbol index beat grep on BOTH latency and payload?
//!
//!   pkx index <repo>          build + persist, report timings
//!   pkx sym <name> [repo]     cold query (load index from disk)
//!   pkx bench <repo>          the comparison harness vs grep/sed
//!   pkx serve <repo>          warm loop, to measure steady-state query cost

use portkit_index::index;

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use index::Index;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let code = match cmd {
        "index" => cmd_index(path_arg(&args, 1)),
        "sym" => cmd_sym(
            args.get(1).map(String::as_str).unwrap_or(""),
            path_arg(&args, 2),
        ),
        "bench" => cmd_bench(path_arg(&args, 1)),
        "serve" => cmd_serve(path_arg(&args, 1)),
        _ => {
            eprintln!("usage: pkx index|sym|bench|serve [args]");
            1
        }
    };
    std::process::exit(code);
}

fn path_arg(args: &[String], i: usize) -> PathBuf {
    args.get(i)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn cmd_index(root: PathBuf) -> i32 {
    let root = root.canonicalize().unwrap_or(root);
    let (idx, stats) = match Index::build(&root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("build failed: {e}");
            return 1;
        }
    };
    let t = Instant::now();
    let bytes = idx.save(&root).unwrap_or(0);
    let write_ms = ms(t);

    println!("indexed {}", root.display());
    println!("  files          {}", idx.file_count);
    println!("  source bytes   {}", idx.bytes_scanned);
    println!("  symbols        {}", idx.symbols.len());
    println!("  unique names   {}", idx.by_name.len());
    println!(
        "  index on disk  {bytes} B  ({:.1}% of source)",
        100.0 * bytes as f64 / idx.bytes_scanned.max(1) as f64
    );
    println!("  walk           {:.1} ms", stats.walk_ms);
    println!("  parse          {:.1} ms", stats.parse_ms);
    println!("  write          {write_ms:.1} ms");
    println!(
        "  TOTAL BUILD    {:.1} ms",
        stats.walk_ms + stats.parse_ms + write_ms
    );
    0
}

fn cmd_sym(name: &str, root: PathBuf) -> i32 {
    let root = root.canonicalize().unwrap_or(root);
    let t = Instant::now();
    let Ok(idx) = Index::load(&root) else {
        eprintln!("no index; run `pkx index` first");
        return 1;
    };
    let load_ms = ms(t);

    let t = Instant::now();
    let mut hits = idx.lookup(name);
    if hits.is_empty() {
        hits = idx.search(name, 10);
    }
    let query_ms = ms(t);

    let mut payload = String::new();
    for s in &hits {
        payload.push_str(&format!(
            "{}:{}-{}  {} {}\n    {}\n",
            idx.file(s),
            s.line_start,
            s.line_end,
            s.kind.as_str(),
            s.name,
            s.signature
        ));
    }
    print!("{payload}");
    if hits.is_empty() {
        // A negative answer from an index is authoritative, and cheap.
        println!(
            "no symbol named `{name}` in {} indexed symbols",
            idx.symbols.len()
        );
    }
    eprintln!(
        "[load {load_ms:.2} ms | query {query_ms:.3} ms | {} hits | {} B returned]",
        hits.len(),
        payload.len()
    );
    0
}

/// Steady state: what a resident service costs per query once loaded.
fn cmd_serve(root: PathBuf) -> i32 {
    let root = root.canonicalize().unwrap_or(root);
    let t = Instant::now();
    let Ok(idx) = Index::load(&root) else {
        eprintln!("no index; run `pkx index` first");
        return 1;
    };
    eprintln!(
        "loaded {} symbols in {:.2} ms; reading names on stdin",
        idx.symbols.len(),
        ms(t)
    );

    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        let t = Instant::now();
        let hits = idx.lookup(name);
        let us = t.elapsed().as_secs_f64() * 1_000_000.0;
        let bytes: usize = hits
            .iter()
            .map(|s| idx.file(s).len() + s.signature.len() + 24)
            .sum();
        let _ = writeln!(out, "{name}\t{}\t{bytes}\t{us:.1}us", hits.len());
        let _ = out.flush();
    }
    0
}

/// The actual experiment: index vs. the grep+sed loop it would replace.
fn cmd_bench(root: PathBuf) -> i32 {
    let root = root.canonicalize().unwrap_or(root);
    let Ok(idx) = Index::load(&root) else {
        eprintln!("no index; run `pkx index` first");
        return 1;
    };

    // Sample real symbols spread across the corpus, not a hand-picked few.
    let mut names: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in idx.symbols.iter().step_by((idx.symbols.len() / 60).max(1)) {
        if s.name.len() > 3 && seen.insert(s.name.as_str()) {
            names.push(&s.name);
        }
        if names.len() >= 40 {
            break;
        }
    }

    println!("repo: {}", root.display());
    println!(
        "{} files, {} source bytes, {} symbols, {} queries\n",
        idx.file_count,
        idx.bytes_scanned,
        idx.symbols.len(),
        names.len()
    );

    // --- warm index ---
    let t = Instant::now();
    let mut idx_bytes = 0usize;
    let mut idx_hits = 0usize;
    for n in &names {
        for s in idx.lookup(n) {
            idx_bytes += idx.file(s).len() + s.signature.len() + 24;
            idx_hits += 1;
        }
    }
    let idx_ms = ms(t);

    // --- grep baseline: what the agent does instead ---
    let t = Instant::now();
    let mut grep_bytes = 0usize;
    for n in &names {
        if let Ok(out) = Command::new("grep")
            .args([
                "-rn",
                "--include=*.rs",
                "--include=*.ts",
                "--include=*.py",
                "--include=*.go",
                n,
            ])
            .arg(&root)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            grep_bytes += out.stdout.len();
        }
    }
    let grep_ms = ms(t);

    let cold = {
        let t = Instant::now();
        let _ = Index::load(&root);
        ms(t)
    };

    println!("{:<26}{:>12}{:>14}", "", "TOTAL ms", "BYTES BACK");
    println!("{}", "-".repeat(52));
    println!(
        "{:<26}{:>12.1}{:>14}",
        "grep (agent's path)", grep_ms, grep_bytes
    );
    println!("{:<26}{:>12.1}{:>14}", "index, warm", idx_ms, idx_bytes);
    println!(
        "{:<26}{:>12.1}{:>14}",
        "index, cold (load once)", cold, idx_bytes
    );
    println!();
    println!(
        "per query:  grep {:.2} ms / {} B   |   index warm {:.4} ms / {} B",
        grep_ms / names.len() as f64,
        grep_bytes / names.len().max(1),
        idx_ms / names.len() as f64,
        idx_bytes / names.len().max(1)
    );
    println!();
    if idx_bytes > 0 && idx_ms > 0.0 {
        println!(
            "  latency:  {:.0}x faster warm, {:.1}x faster including cold load",
            grep_ms / idx_ms.max(0.0001),
            grep_ms / (cold + idx_ms).max(0.0001)
        );
    }
    println!(
        "  payload:  {:.0}x fewer bytes  ({} hits found)",
        grep_bytes as f64 / idx_bytes.max(1) as f64,
        idx_hits
    );
    0
}
