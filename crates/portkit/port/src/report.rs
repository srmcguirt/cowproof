//! Human-readable rendering of a replay report.
//!
//! Optimised for the moment you actually read one: a test just failed and you
//! need to know which field drifted, not to scroll two JSON blobs.

use std::fmt::Write;

use crate::replay::{ReplayReport, Status};

/// Render a report as an indented text summary.
pub fn render(report: &ReplayReport) -> String {
    let mut out = String::new();

    for (tool, passed, total) in report.by_tool() {
        let label = if passed == total { "PASS" } else { "FAIL" };
        let _ = writeln!(out, "  {tool:<28} {passed:>3}/{total:<3}  {label}");

        for outcome in report.outcomes.iter().filter(|o| o.tool == tool) {
            match outcome.status {
                Status::Pass => continue,
                Status::Accepted => {
                    // Not a failure, but never silent: an accepted difference
                    // that stops being justified should be easy to notice.
                    for note in &outcome.accepted {
                        let _ = writeln!(
                            out,
                            "      {} — accepted difference at {}: {}",
                            outcome.id, note.path, note.reason
                        );
                    }
                }
                Status::NotPorted => {
                    let _ = writeln!(out, "      {} — not ported yet", outcome.id);
                }
                Status::Error => {
                    let reason = outcome.error.as_deref().unwrap_or("unknown error");
                    let _ = writeln!(out, "      {} — errored: {reason}", outcome.id);
                }
                Status::Fail => {
                    let _ = writeln!(out, "      fixture {}", outcome.id);
                    for note in &outcome.accepted {
                        let _ =
                            writeln!(out, "        (accepted at {}: {})", note.path, note.reason);
                    }
                    for difference in &outcome.differences {
                        // Differences span multiple lines; indent each so the
                        // report stays a readable tree.
                        for line in difference.to_string().lines() {
                            let _ = writeln!(out, "        {line}");
                        }
                    }
                }
            }
        }
    }

    let _ = write!(
        out,
        "\n  {} passed, {} failed, {} errored, {} not ported",
        report.passed, report.failed, report.errored, report.not_ported
    );
    if report.accepted > 0 {
        let _ = write!(out, ", {} with accepted differences", report.accepted);
    }
    let _ = writeln!(out, " ({} total)", report.total());

    out
}
