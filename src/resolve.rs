//! Dependency resolution against repo snapshots, independent of the
//! package format: frontends describe packages as [`Candidate`]s and supply
//! the version comparison.
//!
//! Like pacman, the resolver doesn't search: each dependency not yet
//! satisfied takes the first package by that name whose version fits, in
//! repo priority order, or else the first package that provides it. What
//! goes into the image is then checked as a whole: every dependency of
//! every package is satisfied by a package going in, no two packages
//! have the same name, and no package conflicts with another. So
//! incompatible versions, also from snapshots of different times, are
//! reported rather than installed.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt;

use anyhow::{Result, bail};

/// How a dependency constrains the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

impl Op {
    fn allows(self, ord: Ordering) -> bool {
        match self {
            Op::Lt => ord.is_lt(),
            Op::Le => ord.is_le(),
            Op::Eq => ord.is_eq(),
            Op::Ge => ord.is_ge(),
            Op::Gt => ord.is_gt(),
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Eq => "=",
            Op::Ge => ">=",
            Op::Gt => ">",
        })
    }
}

/// A dependency or conflict: a name, and possibly a version constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub version: Option<(Op, String)>,
}

impl fmt::Display for Dep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some((op, v)) = &self.version {
            write!(f, "{op}{v}")?;
        }
        Ok(())
    }
}

/// Something a package provides besides its own name, possibly with a
/// version (e.g. a soname with its ABI version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    pub name: String,
    pub version: Option<String>,
}

/// A package available from a repo, as far as resolution needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub version: String,
    pub depends: Vec<Dep>,
    pub provides: Vec<Provide>,
    pub conflicts: Vec<Dep>,
}

/// Compares two versions.
pub type Compare = fn(&str, &str) -> Ordering;

/// A package wanted by name, from any repo or from one (an index into the
/// repos).
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub repo: Option<usize>,
}

/// A chosen package: indexes of its repo and of the candidate in it.
pub type Choice = (usize, usize);

/// Whether `c` satisfies `dep` by its name or what it provides. A
/// versioned dependency is satisfied only by a provide with a version.
fn satisfies(c: &Candidate, dep: &Dep, cmp: Compare) -> bool {
    let fits = |version: &str| match &dep.version {
        None => true,
        Some((op, wanted)) => op.allows(cmp(version, wanted)),
    };
    (c.name == dep.name && fits(&c.version))
        || c.provides.iter().any(|p| {
            p.name == dep.name
                && match (&dep.version, &p.version) {
                    (None, _) => true,
                    (Some(_), Some(v)) => fits(v),
                    (Some(_), None) => false,
                }
        })
}

/// Choose the packages for `targets` and everything they depend on, from
/// `repos` (in priority order). Returns them in the order chosen, targets
/// first.
pub fn resolve(repos: &[&[Candidate]], targets: &[Target], cmp: Compare) -> Result<Vec<Choice>> {
    // Names and provides to candidates, in priority order.
    let mut by_name: HashMap<&str, Vec<Choice>> = HashMap::new();
    let mut by_provide: HashMap<&str, Vec<Choice>> = HashMap::new();
    for (r, candidates) in repos.iter().enumerate() {
        for (i, c) in candidates.iter().enumerate() {
            by_name.entry(&c.name).or_default().push((r, i));
            for p in &c.provides {
                by_provide.entry(&p.name).or_default().push((r, i));
            }
        }
    }
    let get = |(r, i): Choice| &repos[r][i];
    let describe = |choice: Choice| {
        let c = get(choice);
        format!("{} {}", c.name, c.version)
    };

    let mut chosen: Vec<Choice> = Vec::new();
    let mut chosen_names: HashMap<&str, Choice> = HashMap::new();
    // Chosen packages by their names and what they provide.
    let mut chosen_by: HashMap<&str, Vec<Choice>> = HashMap::new();
    // A dependency, the package that needs it (none for a target) and the
    // repo it must come from.
    let mut queue: VecDeque<(Dep, Option<Choice>, Option<usize>)> = targets
        .iter()
        .map(|t| {
            let dep = Dep {
                name: t.name.clone(),
                version: None,
            };
            (dep, None, t.repo)
        })
        .collect();
    while let Some((dep, needed_by, repo)) = queue.pop_front() {
        let in_repo = |&(r, _): &Choice| repo.is_none_or(|repo| r == repo);
        if chosen_by
            .get(dep.name.as_str())
            .into_iter()
            .flatten()
            .any(|&c| in_repo(&c) && satisfies(get(c), &dep, cmp))
        {
            continue;
        }
        let named = by_name.get(dep.name.as_str()).into_iter().flatten();
        let provided = by_provide.get(dep.name.as_str()).into_iter().flatten();
        let Some(&choice) = named
            .chain(provided)
            .filter(|c| in_repo(c))
            .find(|&&c| satisfies(get(c), &dep, cmp))
        else {
            match needed_by {
                Some(by) => bail!("nothing provides {dep}, needed by {}", describe(by)),
                None => bail!("package {dep} not found"),
            }
        };
        let c = get(choice);
        if let Some(&other) = chosen_names.get(c.name.as_str()) {
            let who = needed_by.map_or("the command line".to_owned(), describe);
            bail!(
                "{who} needs {dep}, which {} satisfies, but {} is going in",
                describe(choice),
                describe(other)
            );
        }
        chosen.push(choice);
        chosen_names.insert(&c.name, choice);
        for name in std::iter::once(&c.name).chain(c.provides.iter().map(|p| &p.name)) {
            chosen_by.entry(name).or_default().push(choice);
        }
        for d in &c.depends {
            queue.push_back((d.clone(), Some(choice), None));
        }
    }

    for &a in &chosen {
        for conflict in &get(a).conflicts {
            if let Some(&b) = chosen_by
                .get(conflict.name.as_str())
                .into_iter()
                .flatten()
                .find(|&&b| b != a && satisfies(get(b), conflict, cmp))
            {
                bail!(
                    "{} conflicts with {} ({conflict})",
                    describe(a),
                    describe(b)
                );
            }
        }
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Versions are plain numbers here.
    fn cmp(a: &str, b: &str) -> Ordering {
        a.parse::<u32>().unwrap().cmp(&b.parse().unwrap())
    }

    fn dep(s: &str) -> Dep {
        for (text, op) in [
            (">=", Op::Ge),
            ("<=", Op::Le),
            ("=", Op::Eq),
            ("<", Op::Lt),
            (">", Op::Gt),
        ] {
            if let Some((name, v)) = s.split_once(text) {
                return Dep {
                    name: name.into(),
                    version: Some((op, v.into())),
                };
            }
        }
        Dep {
            name: s.into(),
            version: None,
        }
    }

    /// `name version` followed by `d:dep`, `p:provide` or `c:conflict`.
    fn pkg(s: &str) -> Candidate {
        let mut words = s.split(' ');
        let mut c = Candidate {
            name: words.next().unwrap().into(),
            version: words.next().unwrap().into(),
            depends: vec![],
            provides: vec![],
            conflicts: vec![],
        };
        for w in words {
            let (kind, value) = w.split_once(':').unwrap();
            match kind {
                "d" => c.depends.push(dep(value)),
                "c" => c.conflicts.push(dep(value)),
                "p" => c.provides.push(match value.split_once('=') {
                    Some((n, v)) => Provide {
                        name: n.into(),
                        version: Some(v.into()),
                    },
                    None => Provide {
                        name: value.into(),
                        version: None,
                    },
                }),
                _ => panic!("{w}"),
            }
        }
        c
    }

    fn names(repos: &[&[Candidate]], targets: &[Target]) -> Result<Vec<String>> {
        let chosen = resolve(repos, targets, cmp)?;
        Ok(chosen
            .into_iter()
            .map(|(r, i)| format!("{r}/{}", repos[r][i].name))
            .collect())
    }

    fn target(name: &str) -> Target {
        Target {
            name: name.into(),
            repo: None,
        }
    }

    #[test]
    fn dependencies_and_provides() {
        let core = [
            pkg("bash 5 d:glibc>=2 d:readline d:sh-impl"),
            pkg("glibc 3"),
            pkg("readline 8 d:glibc p:libreadline.so=8"),
            pkg("dash 1 p:sh-impl"),
            pkg("mksh 1 p:sh-impl"),
        ];
        let extra = [
            pkg("readline 9 d:glibc"),
            pkg("tool 1 d:bash d:libreadline.so=8"),
        ];
        let repos: &[&[Candidate]] = &[&core, &extra];
        assert_eq!(
            names(repos, &[target("tool")]).unwrap(),
            ["1/tool", "0/bash", "0/readline", "0/glibc", "0/dash"]
        );
        // A target can be provided, and taken from a given repo.
        assert_eq!(names(repos, &[target("sh-impl")]).unwrap(), ["0/dash"]);
        let qualified = Target {
            name: "readline".into(),
            repo: Some(1),
        };
        assert_eq!(
            names(repos, &[qualified]).unwrap(),
            ["1/readline", "0/glibc"]
        );
        // Already chosen packages satisfy later dependencies.
        assert_eq!(
            names(repos, &[target("mksh"), target("bash")]).unwrap(),
            ["0/mksh", "0/bash", "0/glibc", "0/readline"]
        );
    }

    #[test]
    fn errors() {
        let err = |repos: &[&[Candidate]], targets: &[Target]| {
            format!("{:#}", names(repos, targets).unwrap_err())
        };
        let core = [pkg("a 1 d:b>=2"), pkg("b 1"), pkg("c 1 d:missing")];
        assert_eq!(err(&[&core], &[target("x")]), "package x not found");
        assert_eq!(
            err(&[&core], &[target("a")]),
            "nothing provides b>=2, needed by a 1"
        );
        assert_eq!(
            err(&[&core], &[target("c")]),
            "nothing provides missing, needed by c 1"
        );

        // A newer b from another repo can't go in with the older one.
        let extra = [pkg("b 2")];
        let e = err(&[&core, &extra], &[target("b"), target("a")]);
        assert_eq!(
            e,
            "a 1 needs b>=2, which b 2 satisfies, but b 1 is going in"
        );

        // An unversioned provide doesn't satisfy a versioned dependency.
        let repo = [pkg("a 1 d:lib>=1"), pkg("l 1 p:lib")];
        assert!(err(&[&repo], &[target("a")]).contains("nothing provides lib>=1"));

        let repo = [pkg("a 1 c:b<2"), pkg("b 1"), pkg("c 1 c:b<1")];
        assert_eq!(
            err(&[&repo], &[target("a"), target("b")]),
            "a 1 conflicts with b 1 (b<2)"
        );
        assert_eq!(
            names(&[&repo], &[target("c"), target("b")]).unwrap(),
            ["0/c", "0/b"]
        );
    }
}
