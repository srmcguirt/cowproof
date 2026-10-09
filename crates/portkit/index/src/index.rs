//! Build, persist, and query the symbol index.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::extract::{extract, language_of, Symbol};

#[derive(Debug, Serialize, Deserialize)]
pub struct Index {
    /// Content hash of the corpus, for staleness checks without a rescan.
    pub fingerprint: String,
    pub root: String,
    /// Paths stored once; symbols hold indices into this.
    pub files: Vec<String>,
    pub symbols: Vec<Symbol>,
    /// name -> symbol indices. Persisted rather than rebuilt so a cold query
    /// pays deserialization only, never re-indexing.
    pub by_name: HashMap<String, Vec<u32>>,
    pub built_at: String,
    pub file_count: usize,
    pub bytes_scanned: u64,
}

pub struct BuildStats {
    pub walk_ms: f64,
    pub parse_ms: f64,
}

impl Index {
    /// Refuse to index a tree this large.
    ///
    /// `sym` is registered against the working directory by default, so it can
    /// be invoked somewhere nobody meant to index — a home directory, `/`.
    /// Declining with a number is better than grinding for minutes.
    pub const MAX_FILES: usize = 20_000;

    pub fn build(root: &Path) -> std::io::Result<(Index, BuildStats)> {
        let t0 = Instant::now();

        // ignore::Walk honours .gitignore, so the index reflects the repo the
        // way the developer sees it rather than including build artifacts.
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in ignore::WalkBuilder::new(root)
            .hidden(true)
            .build()
            .flatten()
        {
            if entry.file_type().is_some_and(|t| t.is_file()) {
                let p = entry.into_path();
                if p.to_str().is_some_and(|s| language_of(s).is_some()) {
                    paths.push(p);
                }
            }
        }
        paths.sort();
        if paths.len() > Self::MAX_FILES {
            return Err(std::io::Error::other(format!(
                "{} has {} source files, over the {} limit — point [index] root at a repository",
                root.display(),
                paths.len(),
                Self::MAX_FILES
            )));
        }
        let walk_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = Instant::now();
        let mut files = Vec::with_capacity(paths.len());
        let mut symbols = Vec::new();
        let mut bytes_scanned = 0u64;
        let mut hasher = Fnv::new();

        for path in &paths {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let Some(lang) = language_of(&rel) else {
                continue;
            };

            bytes_scanned += text.len() as u64;
            hasher.write(rel.as_bytes());
            hasher.write(&text.len().to_le_bytes());

            let idx = files.len() as u32;
            symbols.extend(extract(&text, lang, idx));
            files.push(rel);
        }

        let mut by_name: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, sym) in symbols.iter().enumerate() {
            by_name.entry(sym.name.clone()).or_default().push(i as u32);
        }
        let parse_ms = t1.elapsed().as_secs_f64() * 1000.0;

        let index = Index {
            fingerprint: format!("{:016x}", hasher.finish()),
            root: root.to_string_lossy().to_string(),
            file_count: files.len(),
            files,
            symbols,
            by_name,
            built_at: String::new(),
            bytes_scanned,
        };

        Ok((index, BuildStats { walk_ms, parse_ms }))
    }

    /// Where this root's index is cached.
    ///
    /// Central, never inside the indexed tree. Writing `.portkit/cache/` into
    /// the working directory littered 43 files across unrelated repositories —
    /// agents invoke tools from wherever they happen to be, and a cache that
    /// follows them is a cache that vandalises them.
    pub fn cache_path(root: &Path) -> PathBuf {
        let abs = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let mut h = Fnv::new();
        h.write(abs.to_string_lossy().as_bytes());
        let name = format!("{:016x}.json", h.finish());

        let base = match std::env::var_os("PORTKIT_STATE_DIR") {
            Some(dir) => PathBuf::from(dir).join("index"),
            None => std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(".portkit")
                .join("index"),
        };
        base.join(name)
    }

    pub fn save(&self, root: &Path) -> std::io::Result<u64> {
        let path = Self::cache_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(self)?;
        std::fs::write(&path, &bytes)?;
        Ok(bytes.len() as u64)
    }

    pub fn load(root: &Path) -> std::io::Result<Index> {
        let bytes = std::fs::read(Self::cache_path(root))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Exact-name lookup — the hot path.
    pub fn lookup(&self, name: &str) -> Vec<&Symbol> {
        self.by_name
            .get(name)
            .map(|ids| ids.iter().map(|&i| &self.symbols[i as usize]).collect())
            .unwrap_or_default()
    }

    /// Substring fallback, for when the agent half-remembers a name.
    pub fn search(&self, needle: &str, limit: usize) -> Vec<&Symbol> {
        let lower = needle.to_lowercase();
        let mut hits: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&lower))
            .collect();
        // Shorter names first: a query for "run" should surface `run` above
        // `run_with_retries_and_backoff`.
        hits.sort_by_key(|s| (s.name.len(), s.name.clone()));
        hits.truncate(limit);
        hits
    }

    pub fn file(&self, sym: &Symbol) -> &str {
        &self.files[sym.file as usize]
    }
}

/// FNV-1a — good enough to detect corpus change, and dependency-free.
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x1000_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}
