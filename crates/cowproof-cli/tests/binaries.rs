//! The release ships exactly three binaries: `cowproof`, `pk` and `pk-read` (D2). `pk`
//! and `pk-read` stay separate entry points because hooks and shells call them by name;
//! everything else is a `cowproof` subcommand. A new `[[bin]]` anywhere in the workspace,
//! or a `src/main.rs` in a library crate, adds a fourth binary to `cargo install` and to
//! the release tarballs, so this test fails until the design is changed on purpose.

use std::process::Command;

#[test]
fn the_workspace_builds_exactly_cowproof_pk_and_pk_read() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("running cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut bins: Vec<String> = Vec::new();
    for package in metadata["packages"].as_array().unwrap() {
        for target in package["targets"].as_array().unwrap() {
            let is_bin = target["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k == "bin");
            if is_bin {
                bins.push(format!(
                    "{} (package {})",
                    target["name"].as_str().unwrap(),
                    package["name"].as_str().unwrap()
                ));
            }
        }
    }
    bins.sort();
    assert_eq!(
        bins,
        vec![
            "cowproof (package cowproof)".to_string(),
            "pk (package cowproof)".to_string(),
            "pk-read (package cowproof)".to_string(),
        ],
        "the workspace must build exactly cowproof, pk and pk-read, all from the cowproof package"
    );
}

/// `cargo publish` rejects a path dependency with no version, and crates.io rejects a crate
/// with no description. `cargo install cowproof` needs every library it depends on
/// published (`docs/releasing.md`), so each publishable workspace package carries both.
#[test]
fn every_publishable_package_has_a_description_and_versioned_path_dependencies() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("running cargo metadata");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut problems = Vec::new();
    let mut checked = 0;
    for package in metadata["packages"].as_array().unwrap() {
        let name = package["name"].as_str().unwrap();
        // `publish = []` means never published.
        if package["publish"].as_array().is_some_and(|p| p.is_empty()) {
            continue;
        }
        checked += 1;
        if package["description"]
            .as_str()
            .is_none_or(|d| d.trim().is_empty())
        {
            problems.push(format!("{name}: no description"));
        }
        if package["repository"]
            .as_str()
            .is_none_or(|r| r.trim().is_empty())
        {
            problems.push(format!("{name}: no repository"));
        }
        for dep in package["dependencies"].as_array().unwrap() {
            let is_dev = dep["kind"].as_str() == Some("dev");
            if !is_dev && dep["path"].is_string() && dep["req"].as_str() == Some("*") {
                problems.push(format!(
                    "{name}: path dependency {} has no version",
                    dep["name"].as_str().unwrap()
                ));
            }
        }
    }
    assert!(checked >= 14, "only {checked} publishable packages found");
    assert!(problems.is_empty(), "{problems:#?}");
}
