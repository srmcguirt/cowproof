//! The builder ladder and routing (D28, step 1): which builder a lane starts on and which one
//! a `reassign` climbs to.
//!
//! A *rung* is `runtime:model`. The ladder is the ordered list in the base commit's
//! `cowproof.toml` `[ladder] rungs`; `[routing]` names the starting rung (a default, and one
//! per packet class), and a packet header may name one too. The configuration is always read
//! from the lane's BASE commit, never from a working tree, so a lane cannot rewrite its own
//! routing, exactly as the class limits cannot be raised by a patch.
//!
//! The `claude` runtime (Claude Code) and the `openrouter` runtime (OpenCode, D28 step 2) have an
//! adapter. The ladder may list rungs of other runtimes; the runner refuses a lane that would
//! start or be reassigned onto one.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::git_show_optional;

/// The packet classes a header (and so `[routing] classes`) may name.
pub const PACKET_CLASSES: [&str; 4] = ["rust", "crate", "pg", "light"];

/// The ladder when `cowproof.toml` has no `[ladder]` table.
pub const DEFAULT_RUNGS: [&str; 3] = ["claude:haiku", "claude:sonnet", "claude:opus"];

/// The most characters in a model name.
const MODEL_NAME_MAX: usize = 64;

/// A model name goes into a builder's argv, so it is held to a conservative alphabet and never
/// starts like a flag. `/` is in the alphabet because OpenRouter names a model `vendor/name`.
pub fn valid_model_name(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= MODEL_NAME_MAX
        && !model.starts_with('-')
        && model.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']' | '/')
        })
}

/// The CLI that drives a builder. A closed set: a name outside it is refused everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Runtime {
    Claude,
    Openrouter,
    Codex,
}

impl Runtime {
    /// Every runtime, in the order the error messages list them.
    pub const ALL: [Runtime; 3] = [Runtime::Claude, Runtime::Openrouter, Runtime::Codex];

    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Openrouter => "openrouter",
            Self::Codex => "codex",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }

    /// Whether the runner can launch this runtime: Claude Code (D28 step 1), OpenCode for
    /// OpenRouter models (step 2) and Codex with an API key (step 3).
    pub fn has_adapter(self) -> bool {
        matches!(self, Self::Claude | Self::Openrouter | Self::Codex)
    }

    /// The refusal for a rung of this runtime, or `None` when it has an adapter.
    pub fn adapter_refusal(self) -> Option<String> {
        (!self.has_adapter())
            .then(|| format!("runtime `{}` has no adapter yet (D28 step 1)", self.name()))
    }
}

impl fmt::Display for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One step of the ladder: a runtime and the model it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    pub runtime: Runtime,
    pub model: String,
}

impl Rung {
    /// `runtime:model`. A bare model name (no `runtime:`) is read as `claude:<model>`, for
    /// compatibility with the old `--model haiku`. A model that itself contains `:` needs the
    /// explicit `claude:` prefix, because the first `:` always ends the runtime.
    pub fn parse(text: &str) -> Result<Self> {
        let (runtime, model) = match text.split_once(':') {
            Some((prefix, model)) => {
                let runtime = Runtime::from_name(prefix).with_context(|| {
                    format!(
                        "rung {text:?}: unknown runtime {prefix:?} (one of {})",
                        Runtime::ALL.map(Runtime::name).join(", ")
                    )
                })?;
                (runtime, model)
            }
            None => (Runtime::Claude, text),
        };
        if !valid_model_name(model) {
            bail!("rung {text:?}: {model:?} is not a model name");
        }
        Ok(Self {
            runtime,
            model: model.to_string(),
        })
    }

    /// The same runtime and the same model, model names compared without regard to case.
    pub fn same_as(&self, other: &Rung) -> bool {
        self.runtime == other.runtime && self.model.eq_ignore_ascii_case(&other.model)
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.runtime, self.model)
    }
}

/// Where the starting rung of a lane came from, highest precedence first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RungSource {
    /// `cowproof run --model`.
    Flag,
    /// The packet header's `"rung"`.
    Header,
    /// `[routing] classes`.
    Class,
    /// `[routing] default`, or the first rung.
    Default,
}

impl RungSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Header => "header",
            Self::Class => "class",
            Self::Default => "default",
        }
    }
}

/// The ladder and routing of one base commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routing {
    /// The ladder, lowest rung first. Never empty, never a duplicate.
    pub rungs: Vec<Rung>,
    /// The starting rung when nothing else says. Always on the ladder.
    pub default: Rung,
    /// The starting rung per packet class. Every one is on the ladder.
    pub classes: BTreeMap<String, Rung>,
}

impl Default for Routing {
    fn default() -> Self {
        let rungs: Vec<Rung> = DEFAULT_RUNGS
            .iter()
            .map(|r| Rung::parse(r).expect("the default rungs parse"))
            .collect();
        Self {
            default: rungs[0].clone(),
            rungs,
            classes: BTreeMap::new(),
        }
    }
}

impl Routing {
    /// The ladder and routing in a `cowproof.toml`: the defaults, replaced by its `[ladder]`
    /// and `[routing]` tables. A file that does not parse, an unknown key, an empty or
    /// duplicated ladder, an unknown runtime, a bad model name, and a routing rung that is not
    /// on the ladder are all errors. `None` is a repository with no `cowproof.toml`.
    pub fn parse(text: Option<&str>) -> Result<Self> {
        let Some(text) = text else {
            return Ok(Self::default());
        };
        let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
        let mut routing = Self::default();

        if let Some(ladder) = config.get("ladder") {
            let ladder = ladder
                .as_table()
                .context("cowproof.toml: [ladder] must be a table")?;
            refuse_unknown_keys("[ladder]", ladder, &["rungs"])?;
            if let Some(rungs) = ladder.get("rungs") {
                routing.rungs = parse_rungs(rungs)?;
                routing.default = routing.rungs[0].clone();
            }
        }

        if let Some(table) = config.get("routing") {
            let table = table
                .as_table()
                .context("cowproof.toml: [routing] must be a table")?;
            // `profiles` is read by `crate::profiles` (packet profiles per rung, D28 clause 5).
            refuse_unknown_keys("[routing]", table, &["default", "classes", "profiles"])?;
            if let Some(default) = table.get("default") {
                let default = default
                    .as_str()
                    .context("cowproof.toml: [routing] default must be a string")?;
                routing.default = routing
                    .ladder_rung(default)
                    .context("cowproof.toml: [routing] default")?;
            }
            if let Some(classes) = table.get("classes") {
                let classes = classes
                    .as_table()
                    .context("cowproof.toml: [routing] classes must be a table")?;
                for (class, rung) in classes {
                    if !PACKET_CLASSES.contains(&class.as_str()) {
                        bail!(
                            "cowproof.toml: [routing] classes: {class:?} is not a packet class (one of {})",
                            PACKET_CLASSES.join(", ")
                        );
                    }
                    let rung = rung.as_str().with_context(|| {
                        format!("cowproof.toml: [routing] classes {class} must be a string")
                    })?;
                    let rung = routing
                        .ladder_rung(rung)
                        .with_context(|| format!("cowproof.toml: [routing] classes {class}"))?;
                    routing.classes.insert(class.clone(), rung);
                }
            }
        }
        Ok(routing)
    }

    /// The ladder and routing at `commit` of `repo`: the base commit's `cowproof.toml`.
    pub fn at_commit(repo: &Path, commit: &str) -> Result<Self> {
        let text = git_show_optional(repo, commit, "cowproof.toml")?;
        Self::parse(text.as_deref())
            .with_context(|| format!("reading the builder ladder at {commit}"))
    }

    /// `text` as a rung that must be on this ladder.
    pub fn ladder_rung(&self, text: &str) -> Result<Rung> {
        let rung = Rung::parse(text)?;
        match self.rungs.iter().find(|r| r.same_as(&rung)) {
            Some(on_ladder) => Ok(on_ladder.clone()),
            None => bail!(
                "rung {rung} is not on the ladder (rungs: {})",
                self.rungs
                    .iter()
                    .map(Rung::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// The starting rung and where it came from. Precedence: `flag` (`--model`), the packet
    /// header's `rung`, the route for the packet's `class`, then the default. The flag may
    /// name a rung off the ladder (a full model id, say) and is the director's word; a header
    /// rung must be on the ladder, and is checked even when the flag then overrides it.
    pub fn start(
        &self,
        flag: Option<&str>,
        header_rung: Option<&str>,
        class: &str,
    ) -> Result<(Rung, RungSource)> {
        let header = header_rung
            .map(|r| self.ladder_rung(r).context("the packet header's \"rung\""))
            .transpose()?;
        if let Some(flag) = flag {
            let rung = Rung::parse(flag).context("--model")?;
            return Ok((rung, RungSource::Flag));
        }
        if let Some(rung) = header {
            return Ok((rung, RungSource::Header));
        }
        if let Some(rung) = self.classes.get(class) {
            return Ok((rung.clone(), RungSource::Class));
        }
        Ok((self.default.clone(), RungSource::Default))
    }

    /// Where `current` sits on the ladder: an exact rung first, else the rung of the same
    /// runtime whose model name is the longest one contained in `current`'s, so a full model
    /// id (`claude-haiku-5-5`) still finds `claude:haiku`.
    pub fn position(&self, current: &Rung) -> Option<usize> {
        if let Some(i) = self.rungs.iter().position(|r| r.same_as(current)) {
            return Some(i);
        }
        let lower = current.model.to_ascii_lowercase();
        self.rungs
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.runtime == current.runtime && lower.contains(&r.model.to_ascii_lowercase())
            })
            .max_by_key(|(i, r)| (r.model.len(), std::cmp::Reverse(*i)))
            .map(|(i, _)| i)
    }

    /// The rung above `current`. `None` at the top and for a rung that is not on the ladder.
    pub fn next_after(&self, current: &Rung) -> Option<&Rung> {
        self.rungs.get(self.position(current)? + 1)
    }
}

pub(crate) fn refuse_unknown_keys(
    table_name: &str,
    table: &toml::Table,
    known: &[&str],
) -> Result<()> {
    for key in table.keys() {
        if !known.contains(&key.as_str()) {
            bail!(
                "cowproof.toml: {table_name} has an unknown key {key:?} (known: {})",
                known.join(", ")
            );
        }
    }
    Ok(())
}

fn parse_rungs(value: &toml::Value) -> Result<Vec<Rung>> {
    let list = value
        .as_array()
        .context("cowproof.toml: [ladder] rungs must be a list of \"runtime:model\" strings")?;
    if list.is_empty() {
        bail!("cowproof.toml: [ladder] rungs must not be empty");
    }
    let mut rungs: Vec<Rung> = Vec::with_capacity(list.len());
    for item in list {
        let text = item
            .as_str()
            .context("cowproof.toml: [ladder] rungs must be strings")?;
        let rung = Rung::parse(text).context("cowproof.toml: [ladder] rungs")?;
        if rungs.iter().any(|r| r.same_as(&rung)) {
            bail!("cowproof.toml: [ladder] rungs lists {rung} twice");
        }
        rungs.push(rung);
    }
    Ok(rungs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rung(text: &str) -> Rung {
        Rung::parse(text).unwrap()
    }

    fn names(routing: &Routing) -> Vec<String> {
        routing.rungs.iter().map(Rung::to_string).collect()
    }

    /// The whole chain of an error, so a test sees the cause too.
    fn refusal(text: &str) -> String {
        format!("{:#}", Routing::parse(Some(text)).unwrap_err())
    }

    #[test]
    fn no_config_and_no_ladder_table_give_the_three_claude_rungs() {
        let expected = ["claude:haiku", "claude:sonnet", "claude:opus"];
        for text in [None, Some(""), Some("[classes]\nrust = 2\n")] {
            let routing = Routing::parse(text).unwrap();
            assert_eq!(names(&routing), expected, "{text:?}");
            assert_eq!(routing.default, rung("claude:haiku"));
            assert!(routing.classes.is_empty());
        }
    }

    #[test]
    fn a_custom_ladder_replaces_the_default_and_the_first_rung_starts_it() {
        let routing = Routing::parse(Some(
            "[ladder]\nrungs = [\"openrouter:glm-5.3-flash\", \"claude:haiku\", \"codex:gpt-6-luna\", \"claude:opus\"]\n",
        ))
        .unwrap();
        assert_eq!(
            names(&routing),
            [
                "openrouter:glm-5.3-flash",
                "claude:haiku",
                "codex:gpt-6-luna",
                "claude:opus"
            ]
        );
        assert_eq!(routing.default, rung("openrouter:glm-5.3-flash"));
    }

    #[test]
    fn a_bare_model_is_a_claude_rung() {
        assert_eq!(rung("haiku"), rung("claude:haiku"));
        assert_eq!(rung("haiku").runtime, Runtime::Claude);
        let routing =
            Routing::parse(Some("[ladder]\nrungs = [\"haiku\", \"claude:opus\"]\n")).unwrap();
        assert_eq!(names(&routing), ["claude:haiku", "claude:opus"]);
        // The first `:` ends the runtime, so a model with a colon needs its prefix.
        assert_eq!(rung("claude:a.b:c").model, "a.b:c");
        assert!(Rung::parse("a.b:c").is_err());
    }

    #[test]
    fn a_ladder_with_a_duplicate_is_refused() {
        let e =
            refusal("[ladder]\nrungs = [\"claude:haiku\", \"claude:opus\", \"claude:haiku\"]\n");
        assert!(e.contains("claude:haiku twice"), "{e}");
        // A bare name and its claude: form are the same rung; case does not matter.
        let e = refusal("[ladder]\nrungs = [\"haiku\", \"claude:Haiku\"]\n");
        assert!(e.contains("twice"), "{e}");
        // The same model on two runtimes is two rungs.
        assert!(Routing::parse(Some("[ladder]\nrungs = [\"claude:x\", \"codex:x\"]\n")).is_ok());
    }

    #[test]
    fn an_empty_ladder_is_refused() {
        let e = refusal("[ladder]\nrungs = []\n");
        assert!(e.contains("must not be empty"), "{e}");
    }

    #[test]
    fn an_unknown_runtime_is_refused_and_named() {
        let e = refusal("[ladder]\nrungs = [\"claude:haiku\", \"gemini:flash\"]\n");
        assert!(e.contains("unknown runtime \"gemini\""), "{e}");
        assert!(e.contains("claude, openrouter, codex"), "{e}");
    }

    #[test]
    fn a_bad_model_name_is_refused() {
        for bad in ["claude:", "claude:--model", "claude:a b", "claude:a;b", ""] {
            let e = refusal(&format!("[ladder]\nrungs = [\"{bad}\"]\n"));
            assert!(e.contains("is not a model name"), "{bad:?}: {e}");
        }
        let long = format!("claude:{}", "x".repeat(65));
        assert!(Rung::parse(&long).is_err());
        assert!(Rung::parse(&format!("claude:{}", "x".repeat(64))).is_ok());
    }

    #[test]
    fn a_ladder_that_is_not_a_list_of_strings_is_refused() {
        assert!(refusal("[ladder]\nrungs = \"claude:haiku\"\n").contains("must be a list"));
        assert!(refusal("[ladder]\nrungs = [1]\n").contains("must be strings"));
        assert!(refusal("ladder = 3\n").contains("[ladder] must be a table"));
        assert!(refusal("[ladder]\nrung = [\"claude:haiku\"]\n").contains("unknown key \"rung\""));
    }

    #[test]
    fn routing_rungs_must_be_on_the_ladder() {
        let e =
            refusal("[routing]\ndefault = \"claude:opus\"\n[ladder]\nrungs = [\"claude:haiku\"]\n");
        assert!(e.contains("rung claude:opus is not on the ladder"), "{e}");
        assert!(e.contains("[routing] default"), "{e}");
        let e = refusal("[routing]\nclasses = { rust = \"codex:gpt-6-sol\" }\n");
        assert!(
            e.contains("rung codex:gpt-6-sol is not on the ladder"),
            "{e}"
        );
        assert!(e.contains("classes rust"), "{e}");
        // The default ladder applies when there is no [ladder] table.
        assert!(Routing::parse(Some("[routing]\ndefault = \"sonnet\"\n")).is_ok());
    }

    #[test]
    fn routing_names_known_keys_and_known_classes() {
        let e = refusal("[routing]\ndefalt = \"claude:opus\"\n");
        assert!(e.contains("unknown key \"defalt\""), "{e}");
        let e = refusal("[routing]\nclasses = { rusty = \"claude:opus\" }\n");
        assert!(e.contains("\"rusty\" is not a packet class"), "{e}");
        assert!(refusal("[routing]\nclasses = { rust = 1 }\n").contains("must be a string"));
        assert!(refusal("[routing]\ndefault = 1\n").contains("must be a string"));
    }

    #[test]
    fn a_file_that_does_not_parse_is_refused() {
        assert!(refusal("[ladder\n").contains("does not parse"));
    }

    #[test]
    fn routing_reads_the_default_and_the_class_routes() {
        let routing = Routing::parse(Some(
            "[ladder]\nrungs = [\"haiku\", \"sonnet\", \"opus\"]\n[routing]\ndefault = \"sonnet\"\nclasses = { rust = \"opus\", pg = \"claude:sonnet\" }\n",
        ))
        .unwrap();
        assert_eq!(routing.default, rung("claude:sonnet"));
        assert_eq!(routing.classes["rust"], rung("claude:opus"));
        assert_eq!(routing.classes["pg"], rung("claude:sonnet"));
        assert_eq!(routing.classes.len(), 2);
    }

    fn routed() -> Routing {
        Routing::parse(Some(
            "[routing]\ndefault = \"sonnet\"\nclasses = { rust = \"opus\" }\n",
        ))
        .unwrap()
    }

    #[test]
    fn each_source_picks_its_rung() {
        let r = routed();
        let (rung_, source) = r.start(Some("haiku"), None, "light").unwrap();
        assert_eq!((rung_, source), (rung("claude:haiku"), RungSource::Flag));
        let (rung_, source) = r.start(None, Some("claude:haiku"), "light").unwrap();
        assert_eq!((rung_, source), (rung("claude:haiku"), RungSource::Header));
        let (rung_, source) = r.start(None, None, "rust").unwrap();
        assert_eq!((rung_, source), (rung("claude:opus"), RungSource::Class));
        let (rung_, source) = r.start(None, None, "light").unwrap();
        assert_eq!(
            (rung_, source),
            (rung("claude:sonnet"), RungSource::Default)
        );
    }

    #[test]
    fn the_flag_beats_the_header_beats_the_class_beats_the_default() {
        let r = Routing::parse(Some(
            "[routing]\ndefault = \"sonnet\"\nclasses = { rust = \"opus\" }\n",
        ))
        .unwrap();
        // All four name different rungs; each layer removed exposes the next.
        let all = r
            .start(Some("claude-haiku-5-5"), Some("sonnet"), "rust")
            .unwrap();
        assert_eq!(all.1, RungSource::Flag);
        assert_eq!(all.0.model, "claude-haiku-5-5");
        let no_flag = r.start(None, Some("haiku"), "rust").unwrap();
        assert_eq!((no_flag.0, no_flag.1), (rung("haiku"), RungSource::Header));
        let no_header = r.start(None, None, "rust").unwrap();
        assert_eq!(
            (no_header.0, no_header.1),
            (rung("opus"), RungSource::Class)
        );
        let none = r.start(None, None, "pg").unwrap();
        assert_eq!((none.0, none.1), (rung("sonnet"), RungSource::Default));
    }

    #[test]
    fn a_header_rung_off_the_ladder_is_refused_even_when_the_flag_would_override_it() {
        let r = routed();
        for flag in [None, Some("haiku")] {
            let e = format!(
                "{:#}",
                r.start(flag, Some("codex:gpt-6-luna"), "light")
                    .unwrap_err()
            );
            assert!(
                e.contains("rung codex:gpt-6-luna is not on the ladder"),
                "{flag:?}: {e}"
            );
            assert!(e.contains("header"), "{e}");
        }
        let e = format!("{:#}", r.start(Some("--x"), None, "light").unwrap_err());
        assert!(e.contains("--model"), "{e}");
    }

    #[test]
    fn the_ladder_climbs_by_name_and_stops_at_the_top() {
        let r = Routing::default();
        let next = |c: &str| r.next_after(&rung(c)).map(Rung::to_string);
        assert_eq!(next("haiku").as_deref(), Some("claude:sonnet"));
        assert_eq!(next("claude-haiku-5-5").as_deref(), Some("claude:sonnet"));
        assert_eq!(next("sonnet").as_deref(), Some("claude:opus"));
        assert_eq!(next("Opus"), None);
        assert_eq!(next("gpt-6"), None, "not on the ladder");
        assert_eq!(
            next("codex:haiku"),
            None,
            "another runtime's haiku is not this rung"
        );
    }

    #[test]
    fn a_custom_ladder_climbs_across_runtimes_and_prefers_the_longest_name() {
        let r = Routing::parse(Some(
            "[ladder]\nrungs = [\"claude:haiku\", \"codex:gpt-6-luna\", \"claude:haiku-fast\", \"claude:opus\"]\n",
        ))
        .unwrap();
        let next = |c: &str| r.next_after(&rung(c)).map(Rung::to_string);
        assert_eq!(next("claude:haiku").as_deref(), Some("codex:gpt-6-luna"));
        assert_eq!(
            next("codex:gpt-6-luna").as_deref(),
            Some("claude:haiku-fast")
        );
        // A full id containing both names is the longer rung.
        assert_eq!(next("claude-haiku-fast-9").as_deref(), Some("claude:opus"));
        assert_eq!(next("claude:opus"), None);
    }

    #[test]
    fn runtimes_are_a_closed_set_and_every_runtime_has_an_adapter() {
        for runtime in Runtime::ALL {
            assert_eq!(Runtime::from_name(runtime.name()), Some(runtime));
        }
        assert_eq!(Runtime::from_name("Claude"), None);
        assert!(Runtime::Claude.has_adapter());
        assert!(Runtime::Claude.adapter_refusal().is_none());
        assert!(Runtime::Openrouter.has_adapter());
        assert!(Runtime::Openrouter.adapter_refusal().is_none());
        assert!(Runtime::Codex.has_adapter());
        assert!(Runtime::Codex.adapter_refusal().is_none());
    }

    #[test]
    fn model_names_keep_the_old_alphabet() {
        for ok in [
            "opus",
            "claude-haiku-5-5",
            "opus[1m]",
            "a.b_c:d",
            // OpenRouter's `vendor/name`.
            "z-ai/glm-5.3-flash",
        ] {
            assert!(valid_model_name(ok), "{ok}");
        }
        for bad in ["", "-x", "--model", "a b", "a;b", "a\nb", &"x".repeat(65)] {
            assert!(!valid_model_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_base_commits_ladder_is_the_one_read_not_the_working_trees() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(repo)
                .args(["-c", "user.name=t", "-c", "user.email=t@localhost"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
        };
        git(&["init", "-q"]);
        // No cowproof.toml at the base: the defaults.
        std::fs::write(repo.join("README.md"), "x\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "base"]);
        assert_eq!(
            Routing::at_commit(repo, "HEAD").unwrap(),
            Routing::default()
        );
        std::fs::write(
            repo.join("cowproof.toml"),
            "[ladder]\nrungs = [\"claude:opus\"]\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "ladder"]);
        let base = Routing::at_commit(repo, "HEAD").unwrap();
        assert_eq!(names(&base), ["claude:opus"]);
        // An uncommitted edit is not the base.
        std::fs::write(
            repo.join("cowproof.toml"),
            "[ladder]\nrungs = [\"claude:haiku\", \"claude:sonnet\"]\n",
        )
        .unwrap();
        assert_eq!(Routing::at_commit(repo, "HEAD").unwrap(), base);
        // A broken file at the base is an error naming the commit.
        std::fs::write(repo.join("cowproof.toml"), "[ladder]\nrungs = []\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "broken"]);
        let e = format!("{:#}", Routing::at_commit(repo, "HEAD").unwrap_err());
        assert!(e.contains("reading the builder ladder at HEAD"), "{e}");
        assert!(e.contains("must not be empty"), "{e}");
    }
}
