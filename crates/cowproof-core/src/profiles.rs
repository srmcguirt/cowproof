//! Packet profiles per rung (D28, clause 5): what a rung needs from a packet.
//!
//! A *profile* is a named, closed list of [`Requirement`]s. `[profiles.<name>] require = [...]`
//! in the base commit's `cowproof.toml` defines one, and `[routing.profiles]` maps a rung to a
//! profile name. `cowproof lint` resolves the packet's starting rung and requires that rung's
//! profile. A profile shapes the packet only; the proof is the same whichever model writes the
//! patch. Absent `[profiles]` and `[routing.profiles]`, nothing is required.
//!
//! This module reads the configuration. The checks that a packet meets a requirement are in
//! `cowproof-lint`, which reads the packet text.
//!
//! ```toml
//! [profiles.strict]
//! require = ["tests", "mutations", "done-checklist"]
//! [profiles.standard]
//! require = ["checks"]
//! [routing.profiles]
//! "claude:haiku" = "strict"
//! "openrouter:z-ai/glm-5.3-flash" = "strict"
//! ```

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::git_show_optional;
use crate::ladder::{Routing, Rung, refuse_unknown_keys};

/// One thing a profile can require of a packet. A closed set: a name outside it is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Requirement {
    /// A `## Tests` section that lists at least one test by backticked name, with a sentence
    /// saying what it asserts.
    Tests,
    /// A `## Mutations` section with at least one item.
    Mutations,
    /// A numbered list under a heading that has the word "Done" in it.
    DoneChecklist,
    /// The header's `checks` is not empty.
    Checks,
}

impl Requirement {
    /// Every requirement, in the order the error messages list them.
    pub const ALL: [Requirement; 4] = [
        Requirement::Tests,
        Requirement::Mutations,
        Requirement::DoneChecklist,
        Requirement::Checks,
    ];

    /// The name used in `require = [...]` and in lint messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tests => "tests",
            Self::Mutations => "mutations",
            Self::DoneChecklist => "done-checklist",
            Self::Checks => "checks",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The profiles of one base commit and the rung each applies to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profiles {
    /// Every defined profile, by name. A defined profile need not be routed to a rung.
    pub profiles: BTreeMap<String, Vec<Requirement>>,
    /// The profile name per rung, in the order written. Every rung is on the ladder and every
    /// name is defined in `profiles`.
    pub routes: Vec<(Rung, String)>,
}

impl Profiles {
    /// The profiles in a `cowproof.toml`, checked against `routing` (the ladder of the same
    /// file). An unknown key, an unknown requirement, a duplicated requirement, a route for a
    /// rung that is not on the ladder (or listed twice), and a route naming a profile that
    /// `[profiles]` does not define are all errors. `None`, or a file with neither table, is
    /// no requirement at all.
    pub fn parse(text: Option<&str>, routing: &Routing) -> Result<Self> {
        let Some(text) = text else {
            return Ok(Self::default());
        };
        let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
        let mut out = Self::default();

        if let Some(profiles) = config.get("profiles") {
            let profiles = profiles
                .as_table()
                .context("cowproof.toml: [profiles] must be a table")?;
            for (name, profile) in profiles {
                let table_name = format!("[profiles.{name}]");
                let profile = profile
                    .as_table()
                    .with_context(|| format!("cowproof.toml: {table_name} must be a table"))?;
                refuse_unknown_keys(&table_name, profile, &["require"])?;
                let list = profile
                    .get("require")
                    .with_context(|| format!("cowproof.toml: {table_name} needs a `require` list"))?
                    .as_array()
                    .with_context(|| {
                        format!("cowproof.toml: {table_name} require must be a list of names")
                    })?;
                let mut required: Vec<Requirement> = Vec::with_capacity(list.len());
                for item in list {
                    let item = item.as_str().with_context(|| {
                        format!("cowproof.toml: {table_name} require must hold strings")
                    })?;
                    let requirement = Requirement::from_name(item).with_context(|| {
                        format!(
                            "cowproof.toml: {table_name} require: {item:?} is not a requirement (one of {})",
                            Requirement::ALL.map(Requirement::name).join(", ")
                        )
                    })?;
                    if required.contains(&requirement) {
                        bail!("cowproof.toml: {table_name} require lists {requirement} twice");
                    }
                    required.push(requirement);
                }
                out.profiles.insert(name.clone(), required);
            }
        }

        if let Some(table) = config.get("routing") {
            let table = table
                .as_table()
                .context("cowproof.toml: [routing] must be a table")?;
            if let Some(routes) = table.get("profiles") {
                let routes = routes
                    .as_table()
                    .context("cowproof.toml: [routing.profiles] must be a table")?;
                for (rung_text, name) in routes {
                    let name = name.as_str().with_context(|| {
                        format!("cowproof.toml: [routing.profiles] {rung_text:?} must be a string")
                    })?;
                    let rung = routing.ladder_rung(rung_text).with_context(|| {
                        format!("cowproof.toml: [routing.profiles] {rung_text:?}")
                    })?;
                    if out.routes.iter().any(|(r, _)| r.same_as(&rung)) {
                        bail!("cowproof.toml: [routing.profiles] routes {rung} twice");
                    }
                    if !out.profiles.contains_key(name) {
                        bail!(
                            "cowproof.toml: [routing.profiles] {rung_text:?} names profile {name:?}, which [profiles] does not define (defined: {})",
                            if out.profiles.is_empty() {
                                "none".to_string()
                            } else {
                                out.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                            }
                        );
                    }
                    out.routes.push((rung, name.to_string()));
                }
            }
        }
        Ok(out)
    }

    /// The profiles at `commit` of `repo`: the base commit's `cowproof.toml`, never a working
    /// tree. `routing` is the ladder of the same commit.
    pub fn at_commit(repo: &Path, commit: &str, routing: &Routing) -> Result<Self> {
        let text = git_show_optional(repo, commit, "cowproof.toml")?;
        Self::parse(text.as_deref(), routing)
            .with_context(|| format!("reading the packet profiles at {commit}"))
    }

    /// The profile `rung` is routed to: its name and requirements. `None` is no requirement.
    pub fn for_rung(&self, rung: &Rung) -> Option<(&str, &[Requirement])> {
        let (_, name) = self.routes.iter().find(|(r, _)| r.same_as(rung))?;
        let required = self.profiles.get(name)?;
        Some((name.as_str(), required.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LADDER: &str = "[ladder]\nrungs = [\"claude:haiku\", \"openrouter:z-ai/glm-5.3-flash\", \"claude:sonnet\"]\n";

    fn parse(text: &str) -> Result<Profiles> {
        let routing = Routing::parse(Some(text))?;
        Profiles::parse(Some(text), &routing)
    }

    fn refusal(extra: &str) -> String {
        format!("{:#}", parse(&format!("{LADDER}{extra}")).unwrap_err())
    }

    fn rung(text: &str) -> Rung {
        Rung::parse(text).unwrap()
    }

    #[test]
    fn no_config_and_no_profile_tables_require_nothing() {
        let routing = Routing::default();
        for text in [
            None,
            Some(""),
            Some(LADDER),
            Some("[routing]\ndefault = \"haiku\"\n"),
        ] {
            let profiles = Profiles::parse(text, &routing).unwrap();
            assert_eq!(profiles, Profiles::default(), "{text:?}");
            assert_eq!(profiles.for_rung(&rung("claude:haiku")), None);
        }
    }

    #[test]
    fn strict_and_standard_profiles_route_to_their_rungs() {
        let profiles = parse(&format!(
            "{LADDER}[profiles.strict]\nrequire = [\"tests\", \"mutations\", \"done-checklist\"]\n\
             [profiles.standard]\nrequire = [\"checks\"]\n\
             [routing.profiles]\n\"claude:haiku\" = \"strict\"\n\"openrouter:z-ai/glm-5.3-flash\" = \"strict\"\n\"claude:sonnet\" = \"standard\"\n"
        ))
        .unwrap();
        let strict = [
            Requirement::Tests,
            Requirement::Mutations,
            Requirement::DoneChecklist,
        ];
        assert_eq!(
            profiles.for_rung(&rung("claude:haiku")),
            Some(("strict", &strict[..]))
        );
        // A bare name and a different case are the same rung.
        assert_eq!(
            profiles.for_rung(&rung("Haiku")),
            Some(("strict", &strict[..]))
        );
        assert_eq!(
            profiles.for_rung(&rung("openrouter:z-ai/glm-5.3-flash")),
            Some(("strict", &strict[..]))
        );
        assert_eq!(
            profiles.for_rung(&rung("claude:sonnet")),
            Some(("standard", &[Requirement::Checks][..]))
        );
        // A rung with no route has no requirement, even though profiles are defined.
        assert_eq!(profiles.for_rung(&rung("claude:opus")), None);
    }

    #[test]
    fn a_defined_profile_with_no_route_and_an_empty_require_are_allowed() {
        let profiles = parse(&format!(
            "{LADDER}[profiles.spare]\nrequire = [\"checks\"]\n[profiles.none]\nrequire = []\n\
             [routing.profiles]\n\"claude:haiku\" = \"none\"\n"
        ))
        .unwrap();
        assert_eq!(
            profiles.for_rung(&rung("claude:haiku")),
            Some(("none", &[][..]))
        );
        assert_eq!(profiles.for_rung(&rung("claude:sonnet")), None);
    }

    #[test]
    fn an_unknown_key_is_refused_in_a_profile() {
        let e = refusal("[profiles.strict]\nrequire = [\"checks\"]\nneeds = [\"tests\"]\n");
        assert!(
            e.contains("[profiles.strict] has an unknown key \"needs\""),
            "{e}"
        );
        let e = refusal("[profiles.strict]\n");
        assert!(e.contains("needs a `require` list"), "{e}");
    }

    #[test]
    fn an_unknown_or_repeated_requirement_is_refused() {
        let e = refusal("[profiles.strict]\nrequire = [\"tests\", \"coverage\"]\n");
        assert!(
            e.contains("\"coverage\" is not a requirement (one of tests, mutations, done-checklist, checks)"),
            "{e}"
        );
        let e = refusal("[profiles.strict]\nrequire = [\"checks\", \"checks\"]\n");
        assert!(e.contains("lists checks twice"), "{e}");
        let e = refusal("[profiles.strict]\nrequire = \"tests\"\n");
        assert!(e.contains("must be a list"), "{e}");
        let e = refusal("[profiles.strict]\nrequire = [3]\n");
        assert!(e.contains("must hold strings"), "{e}");
        let e = refusal("[profiles]\nstrict = \"tests\"\n");
        assert!(e.contains("[profiles.strict] must be a table"), "{e}");
    }

    #[test]
    fn a_route_for_a_rung_not_on_the_ladder_is_refused() {
        let e = refusal(
            "[profiles.strict]\nrequire = [\"checks\"]\n[routing.profiles]\n\"claude:opus\" = \"strict\"\n",
        );
        assert!(e.contains("[routing.profiles] \"claude:opus\""), "{e}");
        assert!(e.contains("rung claude:opus is not on the ladder"), "{e}");
    }

    #[test]
    fn a_route_naming_an_undefined_profile_is_refused() {
        let e = refusal("[routing.profiles]\n\"claude:haiku\" = \"strict\"\n");
        assert!(
            e.contains(
                "names profile \"strict\", which [profiles] does not define (defined: none)"
            ),
            "{e}"
        );
        let e = refusal(
            "[profiles.standard]\nrequire = [\"checks\"]\n[routing.profiles]\n\"claude:haiku\" = \"strict\"\n",
        );
        assert!(e.contains("(defined: standard)"), "{e}");
        let e = refusal(
            "[profiles.standard]\nrequire = [\"checks\"]\n[routing.profiles]\n\"claude:haiku\" = 3\n",
        );
        assert!(e.contains("must be a string"), "{e}");
    }

    #[test]
    fn a_rung_routed_twice_under_two_spellings_is_refused() {
        let e = refusal(
            "[profiles.standard]\nrequire = [\"checks\"]\n[routing.profiles]\n\"haiku\" = \"standard\"\n\"claude:haiku\" = \"standard\"\n",
        );
        assert!(e.contains("routes claude:haiku twice"), "{e}");
    }

    #[test]
    fn routing_accepts_the_profiles_key_it_does_not_read() {
        // `Routing::parse` still refuses an unknown [routing] key, but `profiles` is known.
        let text = format!("{LADDER}[routing.profiles]\n\"claude:haiku\" = \"x\"\n");
        assert!(Routing::parse(Some(&text)).is_ok());
        assert!(Routing::parse(Some("[routing]\nprofile = \"x\"\n")).is_err());
    }
}
