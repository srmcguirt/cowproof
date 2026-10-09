//! The test the template exists to demonstrate.
//!
//! `fixtures/` records what `examples/python/agent.py` actually returned. This
//! replays every case against the Rust tools and fails if they have drifted —
//! through the direct registry *and* through the MCP envelope, because a tool
//! that is right in Rust but wrong through MCP is still broken for the agent
//! that has to call it.
//!
//! Regenerate the fixtures after an intentional behaviour change:
//!
//! ```text
//! just capture
//! ```

#[tokio::test]
async fn rust_tools_match_the_python_reference() {
    portkit_port::assert_parity("fixtures", &portkit_demo::registry()).await;
}

#[tokio::test]
async fn every_demo_tool_has_at_least_one_fixture() {
    // A tool with no fixtures passes parity vacuously. Catch that here rather
    // than discovering it after shipping a silently unverified port.
    let fixtures =
        portkit_port::load_fixtures(std::path::Path::new("fixtures")).expect("fixtures must load");

    for name in portkit_demo::registry().names() {
        assert!(
            fixtures.iter().any(|f| f.tool == name),
            "`{name}` has no fixtures — capture some before trusting it"
        );
    }
}
