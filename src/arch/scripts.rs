//! Building an image from Arch packages, with their package code: each
//! package's install scriptlet (`.INSTALL`) and the alpm hooks that the
//! packages trigger.
//!
//! The packages are installed in dependency order, then all package code
//! runs in the image in one [`run::run_captured`], as a shell script that
//! skl writes ([`Plan::driver`]): each package's `pre_install` and
//! `post_install`, in the same order, then the `PostTransaction` hooks
//! by name. What the code changed becomes one synthetic package, an
//! overlay, recorded for the build's spec ([`crate::spec`]), so that a
//! build of the same packages installs it instead of running the code
//! again.
//!
//! This differs from pacman, which runs a package's scriptlet right after
//! extracting it, before later packages are there, and `pre_install`
//! before extracting it. `PreTransaction` hooks don't run: pacman reads
//! hooks from the system before installing, and a new image has none.

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::ExitStatus;

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};

use crate::arch::hooks::{self, Hook, When};
use crate::arch::{ArchSection, SECTION, repo, version};
use crate::btrfs;
use crate::diff::{self, Change};
use crate::fds;
use crate::install;
use crate::manifest::{EntryKind, Hash, Package, Section};
use crate::resolve;
use crate::run::{self, Options};
use crate::spec::BuildSpec;
use crate::store::Store;
use crate::worker::{ImportStats, Workers};

/// The version of the way package code runs, part of each build spec:
/// change it whenever the environment or the order of the code changes.
pub const RUNNER: &str = "arch 1";

/// The name of synthetic packages.
pub const SYNTHETIC_NAME: &str = "@arch/scripts";

/// Where the driver and the scriptlets are in the sandbox (a tmpfs).
const DIR: &str = "/run/skl";

/// The shell that runs package code, as pacman's `SCRIPTLET_SHELL`.
const SHELL: &str = "/bin/sh";

/// What a synthetic package's Arch section records: the packages whose
/// scriptlets ran and the hooks, in the order they ran.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptsSection {
    pub scripts: Vec<String>,
    pub hooks: Vec<String>,
}

/// A package's scriptlet to run.
#[derive(Debug)]
struct Script<'a> {
    name: &'a str,
    version: &'a str,
    install: Hash,
}

/// The package code of a build, in the order it runs.
#[derive(Debug)]
pub struct Plan<'a> {
    scripts: Vec<Script<'a>>,
    /// Hooks with the targets that triggered them.
    hooks: Vec<(Hook, Vec<String>)>,
}

impl<'a> Plan<'a> {
    /// The package code of `packages`, which are in the order they are
    /// installed.
    pub fn new(packages: &'a [Package]) -> Result<Plan<'a>> {
        let mut scripts = Vec::new();
        let mut all_hooks = Vec::new();
        let mut installed = Vec::new();
        for pkg in packages {
            let section = ArchSection::of(pkg)?;
            if let Some(index) = section.install {
                scripts.push(Script {
                    name: &pkg.name,
                    version: &pkg.version,
                    install: *pkg.sections[SECTION].blob(index)?,
                });
            }
            all_hooks.push(section.hooks);
            let paths = pkg
                .entries
                .iter()
                .map(|e| match e.kind {
                    EntryKind::Dir => format!("{}/", e.path),
                    _ => e.path.clone(),
                })
                .collect();
            installed.push((pkg.name.as_str(), paths));
        }
        let hooks = hooks::effective(all_hooks.iter().flatten())
            .into_values()
            .filter(|h| h.when == When::PostTransaction)
            .filter_map(|h| Some((h.clone(), h.triggered(&installed)?)))
            .collect();
        Ok(Plan { scripts, hooks })
    }

    /// Whether there is no code to run.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty() && self.hooks.is_empty()
    }

    /// The number of scriptlets and of hooks.
    pub fn counts(&self) -> (usize, usize) {
        (self.scripts.len(), self.hooks.len())
    }

    /// What the synthetic package records about the code.
    pub fn section(&self) -> ScriptsSection {
        ScriptsSection {
            scripts: self.scripts.iter().map(|s| s.name.to_owned()).collect(),
            hooks: self
                .hooks
                .iter()
                .map(|(h, _)| h.name().to_owned())
                .collect(),
        }
    }

    /// The path in the sandbox of the scriptlet of the `i`th script.
    fn script_path(i: usize) -> String {
        format!("{DIR}/install/{i}")
    }

    /// The shell script that runs the code: each scriptlet is sourced in a
    /// subshell of its own (they define functions of the same names) and
    /// its `pre_install` and `post_install` called with the version, if
    /// it defines them; then the hooks run with their targets on stdin if
    /// they need them. Failures are reported and counted, as pacman
    /// reports them and goes on; the script exits with 1 if anything
    /// failed.
    pub fn driver(&self) -> String {
        let mut s = String::from(
            "umask 022\ncd /\nskl_failures=0\n\
             skl_check() {\n\
             \tskl_status=$?\n\
             \tif [ \"$skl_status\" -ne 0 ]; then\n\
             \t\techo \"skl: $1 failed (exit status $skl_status)\" >&2\n\
             \t\tskl_failures=$((skl_failures + 1))\n\
             \tfi\n\
             }\n",
        );
        let total = self.scripts.len() + self.hooks.len();
        for (i, script) in self.scripts.iter().enumerate() {
            let (name, version) = (script.name, quote(script.version));
            let what = format!("the install script of {name}");
            s += &format!(
                "echo {} >&2\n(\n\t. {}\n\tskl_failures=0\n",
                quote(&format!(
                    "skl: ({}/{total}) {what} {}",
                    i + 1,
                    script.version
                )),
                quote(&Self::script_path(i)),
            );
            for function in ["pre_install", "post_install"] {
                s += &format!(
                    "\tif command -v {function} >/dev/null 2>&1; then\n\
                     \t\t{function} {version}\n\
                     \t\tskl_check {}\n\tfi\n",
                    quote(&format!("{function} of {name}"))
                );
            }
            s += &format!("\texit \"$skl_failures\"\n)\nskl_check {}\n", quote(&what));
        }
        for (i, (hook, targets)) in self.hooks.iter().enumerate() {
            let n = self.scripts.len() + i + 1;
            let about = hook.description.as_deref().unwrap_or(hook.name());
            s += &format!(
                "echo {} >&2\n",
                quote(&format!("skl: ({n}/{total}) {about}"))
            );
            let command: Vec<String> = hook.exec.iter().map(|w| quote(w)).collect();
            let command = command.join(" ");
            if hook.needs_targets {
                let targets: Vec<String> = targets.iter().map(|t| quote(t)).collect();
                s += &format!("printf '%s\\n' {} | {command}\n", targets.join(" "));
            } else {
                s += &format!("{command} </dev/null\n");
            }
            s += &format!("skl_check {}\n", quote(&format!("hook {}", hook.name())));
        }
        s += "[ \"$skl_failures\" -eq 0 ]\n";
        s
    }
}

/// `s` quoted for the shell.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The order in which to install `packages`: dependencies first (see
/// [`resolve::install_order`]), by their Arch sections.
pub fn install_order(packages: &[Package]) -> Result<Vec<usize>> {
    let candidates = packages
        .iter()
        .map(repo::package_candidate)
        .collect::<Result<Vec<_>>>()?;
    Ok(resolve::install_order(&candidates, version::vercmp))
}

/// What [`build`] did about package code.
#[derive(Debug)]
pub enum Code {
    /// The packages have none.
    None,
    /// The synthetic package of an earlier build with the same spec was
    /// installed.
    Reused(Hash),
    /// The code ran.
    Ran(Box<Ran>),
}

/// What running package code did.
#[derive(Debug)]
pub struct Ran {
    /// The synthetic package made from the changes.
    pub synthetic: Hash,
    /// The number of scriptlets and of hooks that ran.
    pub scripts: usize,
    pub hooks: usize,
    /// The driver's exit status: failure if any code failed (the failures
    /// were reported on stderr). Then the synthetic package isn't
    /// recorded for reuse.
    pub status: ExitStatus,
    /// Entries added, modified and removed.
    pub changes: (usize, usize, usize),
    /// New file contents added to the store.
    pub stats: ImportStats,
    pub snapshot_removal: btrfs::Removal,
}

/// What [`build`] did.
#[derive(Debug)]
pub struct Built {
    pub report: install::Report,
    pub code: Code,
}

/// Build a new image named `name` in the directory `parent` from the
/// packages with ids `ids`: install them in dependency order, then their
/// package code's synthetic package, which is reused from an earlier build
/// with the same build spec unless `rerun`, and otherwise made by running
/// the code. A synthetic package is recorded for reuse only if all code
/// succeeded.
pub fn build(
    workers: &Workers,
    store: &Store,
    ids: &[Hash],
    parent: BorrowedFd,
    name: &OsStr,
    rerun: bool,
) -> Result<Built> {
    let packages = ids
        .iter()
        .map(|id| store.load_package(id))
        .collect::<Result<Vec<_>>>()?;
    let order = install_order(&packages)?;
    let ids: Vec<Hash> = order.iter().map(|&i| ids[i]).collect();
    let mut packages: Vec<Option<Package>> = packages.into_iter().map(Some).collect();
    let packages: Vec<Package> = order.iter().map(|&i| packages[i].take().unwrap()).collect();
    let plan = Plan::new(&packages)?;
    if plan.is_empty() {
        let report = install::build(workers, store, &ids, parent, name)?;
        return Ok(Built {
            report,
            code: Code::None,
        });
    }
    let spec = store.add_build_spec(&BuildSpec {
        packages: ids.clone(),
        runner: RUNNER.to_owned(),
    })?;
    if !rerun && let Some(synthetic) = store.synthetic(&spec)? {
        let mut all = ids;
        all.push(synthetic);
        let report = install::build(workers, store, &all, parent, name)?;
        return Ok(Built {
            report,
            code: Code::Reused(synthetic),
        });
    }
    let report = install::build(workers, store, &ids, parent, name)?;
    let image = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening the new image")?;
    let ran = run_code(workers, store, &plan, image)?;
    if ran.status.success() {
        store.save_synthetic(&spec, &ran.synthetic)?;
    }
    Ok(Built {
        report,
        code: Code::Ran(Box::new(ran)),
    })
}

/// Run the code of `plan` in the image whose root is `image`, and save
/// what it changed as a synthetic package.
fn run_code(workers: &Workers, store: &Store, plan: &Plan, image: OwnedFd) -> Result<Ran> {
    let driver = fds::holding("skl-driver", plan.driver().as_bytes())?;
    let scripts = plan
        .scripts
        .iter()
        .map(|s| store.open_blob(&s.install))
        .collect::<Result<Vec<_>>>()?;
    let paths: Vec<String> = (0..scripts.len()).map(Plan::script_path).collect();
    let driver_path = format!("{DIR}/run.sh");
    let mut files = vec![(driver.as_fd(), driver_path.as_str())];
    files.extend(
        scripts
            .iter()
            .map(|f| f.as_fd())
            .zip(paths.iter().map(String::as_str)),
    );
    let options = Options {
        files: &files,
        escape_output: true,
    };
    let captured = run::run_captured(
        workers,
        store,
        image.as_fd(),
        OsStr::new(SHELL),
        &[OsString::from(&driver_path)],
        &options,
    )
    .context("running package code")?;
    let mut counts = (0, 0, 0);
    for change in &captured.changes {
        match change {
            Change::Added(_) => counts.0 += 1,
            Change::Modified(_) => counts.1 += 1,
            Change::Removed(_) => counts.2 += 1,
        }
    }
    let (entries, overlay) = diff::overlay(captured.changes);
    let section = Section {
        value: serde_json::to_value(plan.section())?,
        blobs: vec![],
    };
    let synthetic = Package {
        name: SYNTHETIC_NAME.to_owned(),
        version: String::new(),
        entries,
        sections: [(SECTION.to_owned(), section)].into(),
        overlay: Some(overlay),
    };
    let synthetic = store
        .add_package(&synthetic)
        .context("saving what package code changed")?;
    let (scripts, hooks) = plan.counts();
    Ok(Ran {
        synthetic,
        scripts,
        hooks,
        status: captured.status,
        changes: counts,
        stats: captured.stats,
        snapshot_removal: captured.snapshot_removal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Entry;

    #[test]
    fn driver() {
        let hook = hooks::parse(
            "usr/share/libalpm/hooks/a.hook",
            "[Trigger]\nOperation = Install\nType = Path\nTarget = etc/*\n\
             [Action]\nExec = /bin/x 'it''s'\nWhen = PostTransaction\nNeedsTargets\n",
        )
        .unwrap();
        let section = ArchSection {
            install: Some(crate::object::Index { index: 0 }),
            hooks: vec![hook],
            ..ArchSection::default()
        };
        let pkg = Package {
            name: "p".into(),
            version: "1:2'3-1".into(),
            entries: vec![Entry {
                path: "etc".into(),
                kind: EntryKind::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: Default::default(),
            }],
            sections: [section.into_section(vec![Hash([1; 32])]).unwrap()].into(),
            overlay: None,
        };
        let packages = [pkg];
        let plan = Plan::new(&packages).unwrap();
        assert_eq!(plan.counts(), (1, 1));
        let driver = plan.driver();
        assert!(driver.contains("\t. '/run/skl/install/0'\n"), "{driver}");
        assert!(
            driver.contains("\t\tpost_install '1:2'\\''3-1'\n"),
            "{driver}"
        );
        assert!(
            driver.contains("printf '%s\\n' 'etc/' | '/bin/x' 'its'\n"),
            "{driver}"
        );
        assert_eq!(
            plan.section(),
            ScriptsSection {
                scripts: vec!["p".into()],
                hooks: vec!["a.hook".into()],
            }
        );
    }
}
