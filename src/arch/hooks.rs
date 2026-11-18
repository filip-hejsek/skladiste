//! alpm hooks (`alpm-hooks(5)`): reading hook files, and finding the hooks
//! that a new image's packages trigger.
//!
//! Hook files are package content, so they are parsed in the import worker
//! ([`parse`]) and kept in the package's Arch section; the supervisor
//! checks what it gets ([`Hook::validate`]). Hooks in
//! `etc/pacman.d/hooks/` replace those of the same name in
//! `usr/share/libalpm/hooks/`, as in pacman. Masking a hook with a symlink
//! to `/dev/null` isn't supported: such a symlink is an ordinary entry.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// The directories hooks are read from, the one that takes precedence
/// last.
pub const HOOK_DIRS: [&str; 2] = ["usr/share/libalpm/hooks", "etc/pacman.d/hooks"];

/// Largest hook file accepted.
pub const MAX_HOOK_SIZE: u64 = 64 << 10;

/// One hook, as read from its file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    /// The hook file's path in the package, in one of [`HOOK_DIRS`].
    pub path: String,
    pub triggers: Vec<Trigger>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub when: When,
    /// The command and its arguments.
    pub exec: Vec<String>,
    /// Pass the matched targets on stdin, one per line.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_targets: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub abort_on_fail: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    pub operations: Vec<Operation>,
    #[serde(rename = "type")]
    pub kind: TriggerType,
    /// Glob patterns (as `fnmatch` without flags); one starting with `!`
    /// excludes what it matches. The last pattern that matches decides.
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Install,
    Upgrade,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerType {
    /// Paths of files in the packages (directories with a trailing `/`).
    Path,
    /// Names of packages.
    Package,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum When {
    PreTransaction,
    PostTransaction,
}

/// The name of a hook at `path` (in a package), if it is in one of
/// [`HOOK_DIRS`] and its name ends in `.hook`.
pub fn hook_name(path: &str) -> Option<&str> {
    let (dir, name) = path.rsplit_once('/')?;
    (HOOK_DIRS.contains(&dir) && name.len() > ".hook".len() && name.ends_with(".hook"))
        .then_some(name)
}

/// Parse the hook file at `path` with content `text`.
pub fn parse(path: &str, text: &str) -> Result<Hook> {
    parse_inner(path, text).with_context(|| format!("reading hook /{path}"))
}

fn parse_inner(path: &str, text: &str) -> Result<Hook> {
    enum Section {
        None,
        Trigger,
        Action,
    }
    let mut section = Section::None;
    let mut triggers: Vec<(Vec<Operation>, Option<TriggerType>, Vec<String>)> = Vec::new();
    let (mut description, mut when, mut exec) = (None, None, None);
    let (mut needs_targets, mut abort_on_fail, mut depends) = (false, false, Vec::new());
    let mut actions = 0;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        let at = || format!("line {}", n + 1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name {
                "Trigger" => {
                    triggers.push((Vec::new(), None, Vec::new()));
                    Section::Trigger
                }
                "Action" => {
                    actions += 1;
                    Section::Action
                }
                _ => bail!("{}: unknown section [{name}]", at()),
            };
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (line, None),
        };
        let value = || value.with_context(|| format!("{}: {key} needs a value", at()));
        match section {
            Section::None => bail!("{}: {key} outside a section", at()),
            Section::Trigger => {
                let trigger = triggers.last_mut().unwrap();
                match key {
                    "Operation" => trigger.0.push(match value()? {
                        "Install" => Operation::Install,
                        "Upgrade" => Operation::Upgrade,
                        "Remove" => Operation::Remove,
                        v => bail!("{}: unknown operation {v:?}", at()),
                    }),
                    "Type" => {
                        trigger.1 = Some(match value()? {
                            // `File` is pacman's deprecated name for `Path`.
                            "Path" | "File" => TriggerType::Path,
                            "Package" => TriggerType::Package,
                            v => bail!("{}: unknown type {v:?}", at()),
                        })
                    }
                    "Target" => trigger.2.push(value()?.to_owned()),
                    // pacman reports unknown options and goes on.
                    _ => {}
                }
            }
            Section::Action => match key {
                "Description" => description = Some(value()?.to_owned()),
                "When" => {
                    when = Some(match value()? {
                        "PreTransaction" => When::PreTransaction,
                        "PostTransaction" => When::PostTransaction,
                        v => bail!("{}: unknown time {v:?}", at()),
                    })
                }
                "Exec" => exec = Some(split_words(value()?).with_context(at)?),
                "Depends" => depends.push(value()?.to_owned()),
                "NeedsTargets" => needs_targets = true,
                "AbortOnFail" => abort_on_fail = true,
                _ => {}
            },
        }
    }
    ensure!(actions == 1, "a hook needs exactly one [Action]");
    ensure!(!triggers.is_empty(), "a hook needs a [Trigger]");
    let triggers = triggers
        .into_iter()
        .map(|(operations, kind, targets)| {
            ensure!(
                !operations.is_empty() && !targets.is_empty(),
                "a trigger needs an Operation and a Target"
            );
            let kind = kind.context("a trigger needs a Type")?;
            Ok(Trigger {
                operations,
                kind,
                targets,
            })
        })
        .collect::<Result<_>>()?;
    let exec = exec.context("the action has no Exec")?;
    ensure!(!exec.is_empty(), "Exec is empty");
    Ok(Hook {
        path: path.to_owned(),
        triggers,
        description,
        when: when.context("the action has no When")?,
        exec,
        needs_targets,
        abort_on_fail,
        depends,
    })
}

/// Split a command line into words as alpm does (`_alpm_wordsplit`):
/// words are separated by whitespace; single quotes keep everything up to
/// the next one, double quotes too except that a backslash escapes the
/// next character, as it does outside quotes.
pub fn split_words(s: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = s.chars();
    let mut quote = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), c) => word.get_or_insert_default().push(c),
            (_, '\\') => {
                let next = chars.next().context("a backslash at the end")?;
                word.get_or_insert_default().push(next);
            }
            (Some(_), c) => word.get_or_insert_default().push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (None, c) if c.is_ascii_whitespace() => words.extend(word.take()),
            (None, c) => word.get_or_insert_default().push(c),
        }
    }
    ensure!(quote.is_none(), "an unclosed quote");
    words.extend(word);
    Ok(words)
}

impl Hook {
    /// The hook's name: its file name.
    pub fn name(&self) -> &str {
        self.path.rsplit_once('/').map_or(&*self.path, |(_, n)| n)
    }

    /// Check a hook that came from the import worker: in one of
    /// [`HOOK_DIRS`], everything printable, a command, and triggers with
    /// operations and targets.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            hook_name(&self.path).is_some(),
            "bad hook path {:?}",
            self.path
        );
        let strings = self
            .triggers
            .iter()
            .flat_map(|t| &t.targets)
            .chain(&self.exec)
            .chain(&self.depends)
            .chain(&self.description);
        for s in strings {
            ensure!(
                !s.chars().any(char::is_control),
                "hook {}: control characters in {s:?}",
                self.path
            );
        }
        ensure!(!self.exec.is_empty(), "hook {}: no command", self.path);
        ensure!(!self.triggers.is_empty(), "hook {}: no trigger", self.path);
        for t in &self.triggers {
            ensure!(
                !t.operations.is_empty() && !t.targets.is_empty(),
                "hook {}: a trigger without operations or targets",
                self.path
            );
        }
        Ok(())
    }

    /// The targets that trigger the hook when `packages` are installed
    /// into a new image (each with its name and the paths of its entries,
    /// directories with a trailing `/`), sorted, or `None` if it isn't
    /// triggered.
    pub fn triggered(&self, packages: &[(&str, Vec<String>)]) -> Option<Vec<String>> {
        let mut targets = BTreeSet::new();
        let mut triggered = false;
        for t in &self.triggers {
            if !t.operations.contains(&Operation::Install) {
                continue;
            }
            for (name, paths) in packages {
                let candidates: Vec<&str> = match t.kind {
                    TriggerType::Package => vec![name],
                    TriggerType::Path => paths.iter().map(String::as_str).collect(),
                };
                for c in candidates {
                    if matches_patterns(&t.targets, c) {
                        triggered = true;
                        targets.insert(c.to_owned());
                    }
                }
            }
        }
        triggered.then(|| targets.into_iter().collect())
    }
}

/// The hooks of a new image, by name: those of `etc/pacman.d/hooks`
/// replace those of `usr/share/libalpm/hooks` with the same name.
pub fn effective<'a>(hooks: impl IntoIterator<Item = &'a Hook>) -> BTreeMap<&'a str, &'a Hook> {
    let mut by_name: BTreeMap<&str, &Hook> = BTreeMap::new();
    for hook in hooks {
        let etc = |h: &Hook| h.path.starts_with(HOOK_DIRS[1]);
        match by_name.get(hook.name()) {
            Some(other) if etc(other) && !etc(hook) => {}
            _ => {
                by_name.insert(hook.name(), hook);
            }
        }
    }
    by_name
}

/// Whether `s` matches `patterns` as alpm decides it: the last pattern
/// that matches decides, and one starting with `!` excludes.
fn matches_patterns(patterns: &[String], s: &str) -> bool {
    for p in patterns.iter().rev() {
        let (inverted, p) = match p.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, p.as_str()),
        };
        if fnmatch(p.as_bytes(), s.as_bytes()) {
            return !inverted;
        }
    }
    false
}

/// `fnmatch(pattern, s, 0)`: `*` matches any string (also with `/`), `?`
/// any character, `[…]` a set (`!` or `^` first negates it, `a-z` a
/// range), and `\` makes the next character literal. Works on bytes.
pub fn fnmatch(pattern: &[u8], s: &[u8]) -> bool {
    match pattern.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| fnmatch(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && fnmatch(rest, &s[1..]),
        Some((b'[', rest)) => match (bracket(rest), s.split_first()) {
            (Some((set, after)), Some((&c, s))) => set(c) && fnmatch(after, s),
            (Some(_), None) => false,
            // No closing bracket: a literal `[`.
            (None, _) => s.first() == Some(&b'[') && fnmatch(rest, &s[1..]),
        },
        Some((b'\\', rest)) if !rest.is_empty() => {
            s.first() == Some(&rest[0]) && fnmatch(&rest[1..], &s[1..])
        }
        Some((&c, rest)) => s.first() == Some(&c) && fnmatch(rest, &s[1..]),
    }
}

/// The set that a bracket expression starting at `p` (after `[`) stands
/// for, and the pattern after it; `None` if it isn't closed.
#[allow(clippy::type_complexity)]
fn bracket(p: &[u8]) -> Option<(Box<dyn Fn(u8) -> bool + '_>, &[u8])> {
    let (negated, mut p) = match p.first() {
        Some(b'!' | b'^') => (true, &p[1..]),
        _ => (false, p),
    };
    let mut items: Vec<(u8, u8)> = Vec::new();
    let mut first = true;
    loop {
        let (&c, rest) = p.split_first()?;
        if c == b']' && !first {
            p = rest;
            break;
        }
        first = false;
        let (lo, rest) = match (c, rest.split_first()) {
            (b'\\', Some((&e, rest))) => (e, rest),
            _ => (c, rest),
        };
        match rest {
            [b'-', hi, rest @ ..] if *hi != b']' => {
                let (hi, rest) = match (*hi, rest.split_first()) {
                    (b'\\', Some((&e, rest))) => (e, rest),
                    (hi, _) => (hi, rest),
                };
                items.push((lo, hi));
                p = rest;
            }
            _ => {
                items.push((lo, lo));
                p = rest;
            }
        }
    }
    let set = move |c: u8| items.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)) != negated;
    Some((Box::new(set), p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LDCONFIG: &str = "[Trigger]\nOperation = Install\nOperation = Upgrade\n\
        Target = glibc\nType = Package\n\n[Trigger]\nOperation = Install\n\
        Operation = Remove\nTarget = usr/lib/ld.so.conf.d/*\nTarget = !usr/lib/ld.so.conf.d/skip\n\
        Type = Path\n\n[Action]\nDepends = glibc\n\
        Description = Configuring dynamic linker run-time bindings...\n\
        Exec = /usr/bin/ldconfig\nWhen = PostTransaction\nNeedsTargets\n";

    #[test]
    fn parses_hooks() {
        let path = "usr/share/libalpm/hooks/11-glibc-ldconfig.hook";
        let hook = parse(path, LDCONFIG).unwrap();
        hook.validate().unwrap();
        assert_eq!(hook.name(), "11-glibc-ldconfig.hook");
        assert_eq!(hook.when, When::PostTransaction);
        assert_eq!(hook.exec, ["/usr/bin/ldconfig"]);
        assert!(hook.needs_targets && !hook.abort_on_fail);
        assert_eq!(hook.triggers.len(), 2);
        assert_eq!(hook.triggers[1].kind, TriggerType::Path);
        assert_eq!(hook.triggers[1].targets.len(), 2);
        for bad in [
            "Exec = x\n",
            "[Action]\nExec = x\nWhen = PostTransaction\n",
            "[Trigger]\nOperation = Install\nType = Package\nTarget = x\n",
            "[Trigger]\nOperation = Install\nTarget = x\n[Action]\nExec = x\nWhen = PostTransaction\n",
            "[Trigger]\nOperation = Install\nType = Package\nTarget = x\n[Action]\nExec = x\n",
            "[Trigger]\nOperation = Never\nType = Package\nTarget = x\n[Action]\nExec = x\nWhen = PostTransaction\n",
            "[Trigger]\nOperation = Install\nType = Package\nTarget = x\n[Action]\nExec = 'x\nWhen = PostTransaction\n",
            "[Other]\n",
        ] {
            assert!(parse(path, bad).is_err(), "{bad:?}");
        }
        assert_eq!(hook_name(path), Some("11-glibc-ldconfig.hook"));
        assert_eq!(hook_name("etc/pacman.d/hooks/a.hook"), Some("a.hook"));
        assert_eq!(hook_name("etc/pacman.d/hooks/.hook"), None);
        assert_eq!(hook_name("usr/share/libalpm/hooks/a.txt"), None);
        assert_eq!(hook_name("usr/share/libalpm/hooks/x/a.hook"), None);
    }

    #[test]
    fn splits_words() {
        let split = |s| split_words(s).unwrap();
        assert_eq!(
            split("/usr/bin/rm --force  a"),
            ["/usr/bin/rm", "--force", "a"]
        );
        assert_eq!(
            split(r#"sh -c 'echo "a b"' x"y z"\ w"#),
            ["sh", "-c", r#"echo "a b""#, "xy z w"]
        );
        assert_eq!(split(r#"'' "\"" a\'"#), ["", "\"", "a'"]);
        assert!(split_words("a\\").is_err());
        assert!(split_words("\"a").is_err());
    }

    #[test]
    fn globs() {
        let m = |p: &str, s: &str| fnmatch(p.as_bytes(), s.as_bytes());
        assert!(m("usr/lib/*", "usr/lib/a/b"));
        assert!(m("usr/lib/*", "usr/lib/"));
        assert!(!m("usr/lib/*", "usr/lib"));
        assert!(m(
            "usr/lib/modules/*/vmlinuz",
            "usr/lib/modules/6.1/vmlinuz"
        ));
        assert!(m("a?c", "abc") && !m("a?c", "ac"));
        assert!(m("[a-c]x", "bx") && !m("[!a-c]x", "bx") && m("[^a-c]x", "dx"));
        assert!(m("[]]", "]") && m("[a-]", "-"));
        assert!(m("[", "[") && m("a\\*", "a*") && !m("a\\*", "ab"));
        assert!(m("*.hook", ".hook"));
    }

    #[test]
    fn triggers() {
        let hook = parse("usr/share/libalpm/hooks/l.hook", LDCONFIG).unwrap();
        let pkg = |name, paths: &[&str]| {
            (
                name,
                paths.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>(),
            )
        };
        let other = pkg(
            "other",
            &["usr/lib/ld.so.conf.d/", "usr/lib/ld.so.conf.d/a"],
        );
        assert_eq!(
            hook.triggered(std::slice::from_ref(&other)).unwrap(),
            ["usr/lib/ld.so.conf.d/", "usr/lib/ld.so.conf.d/a"]
        );
        let skipped = pkg("other", &["usr/lib/ld.so.conf.d/skip"]);
        assert_eq!(hook.triggered(std::slice::from_ref(&skipped)), None);
        let glibc = pkg("glibc", &[]);
        assert_eq!(hook.triggered(&[glibc, skipped]).unwrap(), ["glibc"]);
        // Hooks in /etc replace those of the same name.
        let etc = parse("etc/pacman.d/hooks/l.hook", LDCONFIG).unwrap();
        for hooks in [[&hook, &etc], [&etc, &hook]] {
            let by_name = effective(hooks);
            assert_eq!(by_name.len(), 1);
            assert_eq!(by_name["l.hook"].path, etc.path);
        }
    }
}
