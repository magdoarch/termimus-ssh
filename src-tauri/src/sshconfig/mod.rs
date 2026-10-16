//! Reads OpenSSH's client configuration (`~/.ssh/config`) so hosts can be
//! imported, following ssh_config(5) for what Termimus can represent:
//!
//! - `Host` blocks with `*` / `?` / `!` patterns; the first value obtained
//!   for each keyword wins, options before the first `Host` apply to all
//! - `Include` (relative to `~/.ssh`, `*`/`?` globs in the file name),
//!   expanded in place like ssh does
//! - `HostName` with `%h`, `~` and `%d` in paths, quoted values, comments
//! - `Match all` acts like `Host *`; other `Match` blocks can't be evaluated
//!   here and are skipped (reported as a warning)

pub mod import;
pub mod known_hosts;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 8;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
struct Block {
    patterns: Vec<String>,
    /// `Match` blocks other than `Match all` never apply.
    skipped: bool,
    options: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SshConfig {
    blocks: Vec<Block>,
    pub warnings: Vec<String>,
}

/// The effective settings for one host alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: Option<String>,
    /// First `IdentityFile`, expanded to an absolute path.
    pub identity_file: Option<PathBuf>,
    pub proxy_jump: Option<String>,
    pub proxy_command: bool,
}

/// One hop of `ProxyJump [user@]host[:port]` (also `ssh://` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl SshConfig {
    /// Load `path`; relative `Include`s resolve against `home/.ssh`.
    pub fn load(path: &Path, home: &Path) -> std::io::Result<Self> {
        let mut config = SshConfig::default();
        let mut lines = Vec::new();
        let text = read_limited(path, MAX_CONFIG_BYTES)?;
        expand_lines(&text, home, 0, &mut lines, &mut config.warnings);
        config.build(lines);
        Ok(config)
    }

    pub fn parse_str(text: &str, home: &Path) -> Self {
        let mut config = SshConfig::default();
        let mut lines = Vec::new();
        expand_lines(text, home, 0, &mut lines, &mut config.warnings);
        config.build(lines);
        config
    }

    fn build(&mut self, lines: Vec<(String, String)>) {
        // Options before the first Host/Match apply to every host.
        self.blocks.push(Block {
            patterns: vec!["*".to_string()],
            skipped: false,
            options: Vec::new(),
        });
        let mut warned_match = false;
        for (keyword, value) in lines {
            match keyword.as_str() {
                "host" => self.blocks.push(Block {
                    patterns: args(&value),
                    skipped: false,
                    options: Vec::new(),
                }),
                "match" => {
                    let criteria = args(&value);
                    let all = criteria.len() == 1 && criteria[0].eq_ignore_ascii_case("all");
                    if !all && !warned_match {
                        warned_match = true;
                        self.warnings.push(
                            "`Match` blocks can't be evaluated outside ssh and were skipped.".to_string(),
                        );
                    }
                    self.blocks.push(Block {
                        patterns: vec!["*".to_string()],
                        skipped: !all,
                        options: Vec::new(),
                    });
                }
                _ => {
                    if let Some(block) = self.blocks.last_mut() {
                        block.options.push((keyword, value));
                    }
                }
            }
        }
    }

    /// Concrete host aliases (no wildcards or negations), in file order.
    pub fn aliases(&self) -> Vec<String> {
        let mut seen = Vec::<String>::new();
        for block in &self.blocks[1..] {
            for pattern in &block.patterns {
                let concrete = !pattern.contains(['*', '?']) && !pattern.starts_with('!');
                if concrete && !block.skipped && !seen.iter().any(|s| s == pattern) {
                    seen.push(pattern.clone());
                }
            }
        }
        seen
    }

    pub fn resolve(&self, alias: &str, home: &Path) -> ResolvedHost {
        let mut options: HashMap<&str, &str> = HashMap::new();
        for block in &self.blocks {
            if block.skipped || !host_patterns_match(&block.patterns, alias) {
                continue;
            }
            for (keyword, value) in &block.options {
                options.entry(keyword.as_str()).or_insert(value.as_str());
            }
        }
        let first_arg = |keyword: &str| options.get(keyword).and_then(|v| args(v).into_iter().next());

        let hostname = first_arg("hostname")
            .map(|h| expand_tokens(&h, alias, home))
            .unwrap_or_else(|| alias.to_string());
        let port = first_arg("port").and_then(|p| p.parse::<u16>().ok()).filter(|p| *p != 0).unwrap_or(22);
        let identity_file = first_arg("identityfile")
            .filter(|f| !f.eq_ignore_ascii_case("none"))
            .map(|f| expand_path(&f, alias, home));
        let proxy_jump = first_arg("proxyjump").filter(|j| !j.eq_ignore_ascii_case("none"));
        let proxy_command = first_arg("proxycommand").is_some_and(|c| !c.eq_ignore_ascii_case("none"));

        ResolvedHost {
            alias: alias.to_string(),
            hostname,
            port,
            user: first_arg("user"),
            identity_file,
            proxy_jump,
            proxy_command,
        }
    }
}

fn read_limited(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(std::io::Error::other(format!("{} is too large", path.display())));
    }
    std::fs::read_to_string(path)
}

/// Split into (lowercase keyword, raw value) lines, expanding `Include`s in place.
fn expand_lines(text: &str, home: &Path, depth: usize, out: &mut Vec<(String, String)>, warnings: &mut Vec<String>) {
    for line in text.lines() {
        let Some((keyword, value)) = split_line(line) else { continue };
        if keyword != "include" {
            out.push((keyword, value));
            continue;
        }
        if depth >= MAX_INCLUDE_DEPTH {
            warnings.push("`Include` nested too deeply; stopped following it.".to_string());
            continue;
        }
        for pattern in args(&value) {
            for file in include_files(&pattern, home) {
                match read_limited(&file, MAX_CONFIG_BYTES) {
                    Ok(text) => expand_lines(&text, home, depth + 1, out, warnings),
                    Err(e) => warnings.push(format!("Could not read included {}: {e}", file.display())),
                }
            }
        }
    }
}

fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let keyword = line[..end].to_ascii_lowercase();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    Some((keyword, rest.to_string()))
}

/// Whitespace-separated arguments; double quotes group, a token starting
/// with `#` begins a comment.
fn args(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut in_quotes = false;
    for c in value.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                in_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if in_token {
                    out.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            '#' if !in_quotes && !in_token => break,
            c => {
                current.push(c);
                in_token = true;
            }
        }
    }
    if in_token {
        out.push(current);
    }
    out
}

/// Files named by an `Include` argument, sorted like glob(3).
fn include_files(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let path = expand_tilde(pattern, home);
    let path = if path.is_absolute() { path } else { home.join(".ssh").join(path) };
    let file_pattern = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    if !file_pattern.contains(['*', '?']) {
        return if path.is_file() { vec![path] } else { Vec::new() };
    }
    let Some(dir) = path.parent() else { return Vec::new() };
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| glob_match(&file_pattern, name)) && entry.path().is_file()
        })
        .map(|entry| entry.path())
        .collect();
    files.sort();
    files
}

fn expand_tilde(value: &str, home: &Path) -> PathBuf {
    if value == "~" {
        home.to_path_buf()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(value)
    }
}

/// `%h` (host alias), `%d` (home directory) and `%%`.
fn expand_tokens(value: &str, alias: &str, home: &Path) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(alias),
            Some('d') => out.push_str(&home.to_string_lossy()),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Paths in the config: `~` and tokens expanded, relative paths taken from home.
fn expand_path(value: &str, alias: &str, home: &Path) -> PathBuf {
    let path = expand_tilde(&expand_tokens(value, alias, home), home);
    if path.is_absolute() { path } else { home.join(path) }
}

/// `*` / `?` glob, case-insensitive (ssh host matching is).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut star_ti) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// A `Host` line applies when a positive pattern matches and no negated one does.
fn host_patterns_match(patterns: &[String], host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_match(negated, host) {
                return false;
            }
        } else if glob_match(pattern, host) {
            matched = true;
        }
    }
    matched
}

/// Parse a ProxyJump value with a single hop; multi-hop chains aren't supported.
pub fn parse_jump(spec: &str) -> Result<JumpSpec, String> {
    let spec = spec.trim();
    if spec.contains(',') {
        return Err("multi-hop ProxyJump isn't supported".to_string());
    }
    let spec = spec.strip_prefix("ssh://").unwrap_or(spec);
    let (user, rest) = match spec.rsplit_once('@') {
        Some((user, rest)) => (Some(user.to_string()), rest),
        None => (None, spec),
    };
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or("invalid ProxyJump address")?;
        let port = after.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| "invalid ProxyJump port")).transpose()?;
        (host.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                (host.to_string(), Some(port.parse::<u16>().map_err(|_| "invalid ProxyJump port")?))
            }
            _ => (rest.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("invalid ProxyJump host".to_string());
    }
    Ok(JumpSpec { user, host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/home/me")
    }

    const SAMPLE: &str = r#"
# global defaults
ServerAliveInterval 30

Host web prod-db
    HostName %h.example.com
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_work

Host prod-db
    # first value wins: web/prod-db block above already set these
    User ignored
    ProxyJump bastion

Host bastion
    HostName=203.0.113.10
    User "ops team"   # trailing comment
    IdentityFile "~/.ssh/my keys/bastion"

Host *.internal !secret.internal
    User internal-user

Host *
    User fallback
    IdentityFile ~/.ssh/id_ed25519
"#;

    #[test]
    fn resolves_first_value_wins_with_defaults() {
        let config = SshConfig::parse_str(SAMPLE, &home());
        assert_eq!(config.aliases(), vec!["web", "prod-db", "bastion"]);

        let db = config.resolve("prod-db", &home());
        assert_eq!(db.hostname, "prod-db.example.com");
        assert_eq!(db.user.as_deref(), Some("deploy"));
        assert_eq!(db.port, 2222);
        assert_eq!(db.identity_file, Some(PathBuf::from("/home/me/.ssh/id_work")));
        assert_eq!(db.proxy_jump.as_deref(), Some("bastion"));

        let bastion = config.resolve("bastion", &home());
        assert_eq!(bastion.hostname, "203.0.113.10");
        assert_eq!(bastion.user.as_deref(), Some("ops team"));
        assert_eq!(bastion.port, 22);
        assert_eq!(bastion.identity_file, Some(PathBuf::from("/home/me/.ssh/my keys/bastion")));
    }

    #[test]
    fn wildcards_and_negations() {
        let config = SshConfig::parse_str(SAMPLE, &home());
        assert_eq!(config.resolve("app.internal", &home()).user.as_deref(), Some("internal-user"));
        // Negated: falls through to `Host *`.
        assert_eq!(config.resolve("secret.internal", &home()).user.as_deref(), Some("fallback"));
        let other = config.resolve("10.1.2.3", &home());
        assert_eq!(other.hostname, "10.1.2.3");
        assert_eq!(other.identity_file, Some(PathBuf::from("/home/me/.ssh/id_ed25519")));
    }

    #[test]
    fn match_blocks_are_skipped_but_match_all_applies() {
        let config = SshConfig::parse_str(
            "Match host foo exec \"true\"\n  User nope\nMatch all\n  Port 2200\nHost foo\n  HostName 10.0.0.1\n",
            &home(),
        );
        let foo = config.resolve("foo", &home());
        assert_eq!(foo.user, None);
        assert_eq!(foo.port, 2200);
        assert_eq!(config.warnings.len(), 1);
    }

    #[test]
    fn proxy_command_and_none_values() {
        let config = SshConfig::parse_str(
            "Host a\n  ProxyCommand nc %h %p\n  IdentityFile none\nHost b\n  ProxyJump none\n",
            &home(),
        );
        let a = config.resolve("a", &home());
        assert!(a.proxy_command);
        assert_eq!(a.identity_file, None);
        assert_eq!(config.resolve("b", &home()).proxy_jump, None);
    }

    #[test]
    fn includes_with_globs() {
        let dir = std::env::temp_dir().join(format!("termimus-sshcfg-{}", std::process::id()));
        let ssh = dir.join(".ssh");
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        std::fs::write(ssh.join("config.d/10-work"), "Host work\n  HostName 10.0.0.5\n").unwrap();
        std::fs::write(ssh.join("config.d/20-home"), "Host nas\n  User admin\n").unwrap();
        std::fs::write(ssh.join("config.d/README.txt"), "Host ignored-by-glob\n").unwrap();
        let config = SshConfig::parse_str("Include config.d/??-*\nHost local\n", &dir);
        assert_eq!(config.aliases(), vec!["work", "nas", "local"]);
        assert_eq!(config.resolve("work", &dir).hostname, "10.0.0.5");
        assert_eq!(config.resolve("nas", &dir).user.as_deref(), Some("admin"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn jump_specs() {
        assert_eq!(parse_jump("bastion").unwrap(), JumpSpec { user: None, host: "bastion".into(), port: None });
        assert_eq!(
            parse_jump("ops@203.0.113.10:2200").unwrap(),
            JumpSpec { user: Some("ops".into()), host: "203.0.113.10".into(), port: Some(2200) }
        );
        assert_eq!(parse_jump("ssh://me@[2001:db8::1]:22").unwrap().host, "2001:db8::1");
        assert!(parse_jump("a,b").is_err());
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.example.com", "web.EXAMPLE.com"));
        assert!(glob_match("db-??", "db-01"));
        assert!(!glob_match("db-??", "db-001"));
        assert!(glob_match("*", ""));
    }
}
