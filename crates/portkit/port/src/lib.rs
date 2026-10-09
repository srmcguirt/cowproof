//! Golden-fixture parity harness.
//!
//! The problem this solves: you have a Python agentic process with a test
//! suite you trust, and you want the same behaviour in Rust. "I read both
//! implementations and they look equivalent" is not a claim CI can check.
//!
//! So capture what Python actually does on a set of cases, commit the results
//! as fixtures, and replay them against the Rust port on every build:
//!
//! ```text
//! pk port capture --cmd 'python agent.py' --cases cases.jsonl --out fixtures/
//! pk port replay  --fixtures fixtures/
//! ```
//!
//! Replay runs through either the registry directly or the MCP `tools/call`
//! envelope ([`Surface`]), so you can prove an agent gets the same answer the
//! Python original gave.
//!
//! # In tests
//!
//! ```no_run
//! # use portkit_core::Registry;
//! #[tokio::test]
//! async fn matches_the_python_reference() {
//!     portkit_port::assert_parity("fixtures/", &my_registry()).await;
//! }
//! # fn my_registry() -> Registry { Registry::new() }
//! ```

pub mod capture;
pub mod fixture;
pub mod replay;
pub mod report;

pub use capture::{capture, CaptureOptions, CaptureReport};
pub use fixture::{load_cases, load_fixtures, AcceptedDifference, Case, Fixture};
pub use replay::{
    replay, replay_fixtures, CaseOutcome, ReplayOptions, ReplayReport, Status, Surface,
};
pub use report::render;

use std::path::Path;

use portkit_core::Registry;

/// Replay fixtures and panic with a readable diff if the port has drifted.
///
/// Checks both surfaces: a tool that is correct when called directly but wrong
/// through MCP is still broken for the agent that has to use it.
pub async fn assert_parity(fixtures: impl AsRef<Path>, registry: &Registry) {
    let root = fixtures.as_ref();

    for surface in [Surface::Direct, Surface::Mcp] {
        let opts = ReplayOptions {
            surface,
            ..Default::default()
        };
        let report = replay(root, registry, &opts)
            .await
            .unwrap_or_else(|e| panic!("could not replay fixtures at {}: {e}", root.display()));

        assert!(
            report.total() > 0,
            "no fixtures found at {} — capture some before asserting parity",
            root.display()
        );

        assert!(
            report.is_success(),
            "parity failed on the {surface} surface\n\n{}",
            render(&report)
        );
    }
}
