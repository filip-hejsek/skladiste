//! `skl arch`: commands for Arch Linux packages and repos.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use clap::{Args, Subcommand};
use rustix::fs::{Mode, OFlags};

use skladiste::arch::keyring::{self, NoKeyring, Outcome, Record};
use skladiste::arch::packages::{
    self, Chosen, Context, Event, Imported, LocalFile, LocalPackage, Source,
};
use skladiste::arch::repo::{self, LOCAL_REPO as LOCAL, repo_id};
use skladiste::arch::scripts::{self, Code};
use skladiste::arch::verify::{KeyringFiles, Verifier};
use skladiste::http::Url;
use skladiste::resolve::Target;
use skladiste::store::Store;
use skladiste::worker::Workers;

use super::mib;

#[derive(Args)]
pub(crate) struct ArchArgs {
    #[command(subcommand)]
    command: ArchCommand,
}

#[derive(Subcommand)]
enum ArchCommand {
    /// Import Arch package files into the store, as the repo `@local`.
    ///
    /// Packages are files or http(s) URLs. The signature is read from the
    /// same path or URL with `.sig` appended. Builds can use the imported
    /// packages with `--repo @local`. Downloads are kept in the store's
    /// `downloads/@arch/@local/` directory and not downloaded again for the
    /// same file name. Redirects are not followed.
    Import {
        /// Package files or URLs.
        #[arg(required = true, value_name = "FILE|URL")]
        packages: Vec<OsString>,
    },
    /// Create a new image subvolume containing the given packages and
    /// their dependencies.
    ///
    /// The packages are installed in dependency order; then their install
    /// scripts and the alpm hooks they trigger run in the image, as with
    /// `skl run`. What that code changed is kept in the store and
    /// installed instead of running the code again when the same packages
    /// are built again (unless --rerun-scripts).
    Build {
        /// Path of the new subvolume (must not exist).
        #[arg(short, long)]
        output: PathBuf,
        /// Download the databases of the repos first, as `skl arch sync`
        /// does.
        #[arg(long)]
        sync: bool,
        /// Download packages that aren't in the store yet. Without this,
        /// a build uses the network only for `--sync`.
        #[arg(long)]
        fetch: bool,
        /// Run the packages' install scripts and hooks even if an earlier
        /// build of the same packages ran them, and keep what they change
        /// now instead.
        #[arg(long)]
        rerun_scripts: bool,
        /// Repo to take packages from (repeatable, in priority order): a
        /// repo added with `skl arch repo add`, of which the latest sync is
        /// used, or `@local` for the packages imported with `skl arch
        /// import`. Repos are given by name (`core`) or by id
        /// (`@arch/core`).
        #[arg(long = "repo", value_name = "REPO", required = true)]
        repos: Vec<String>,
        /// Package names: `NAME`, or `REPO/NAME` to take it from that repo.
        #[arg(required = true, value_name = "PACKAGE")]
        packages: Vec<String>,
    },
    /// Manage the packages imported into `@local`.
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
    /// Manage Arch repos.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Manage the keyring that package signatures are verified with.
    ///
    /// The keyring is kept in the store. It is set from files with `init`
    /// and updated from the archlinux-keyring package of a repo with
    /// `update`. Importing packages needs it.
    Keyring {
        #[command(subcommand)]
        command: KeyringCommand,
    },
    /// Download the databases of Arch repos.
    ///
    /// Every version is kept; builds use the latest. Repos synced together
    /// get their new versions only once all of them were downloaded and
    /// read. A database that didn't change on the server since the last
    /// sync isn't downloaded again.
    Sync {
        /// Repos to sync [default: all].
        repos: Vec<String>,
    },
}

#[derive(Subcommand)]
enum LocalCommand {
    /// List the packages imported into `@local`: name, version and id,
    /// sorted by name, newest version first.
    List,
    /// Remove packages from `@local`, with the downloads kept for them.
    ///
    /// Their contents stay in the store until `skl gc`. Fails without
    /// removing anything if a package isn't in `@local`.
    Remove {
        /// Packages: `NAME` for all its versions, or `NAME=VERSION`.
        #[arg(required = true, value_name = "PACKAGE")]
        packages: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RepoCommand {
    /// Add an Arch repo.
    Add {
        /// Name of the repo in skl.
        name: String,
        /// Server URL in the format of pacman's `Server`, e.g.
        /// `https://geo.mirror.pkgbuild.com/$repo/os/$arch` ($arch is
        /// x86_64).
        server: String,
        /// Name of the database on the server (`core` for core.db)
        /// [default: NAME].
        #[arg(long)]
        db: Option<String>,
    },
    /// List Arch repos with their server and the time of their latest
    /// sync.
    List,
}

#[derive(Subcommand)]
enum KeyringCommand {
    /// Make the Arch keyring files PREFIX.gpg, PREFIX-trusted and
    /// PREFIX-revoked the store's keyring, replacing the one there.
    ///
    /// These are trusted as given: use the keyring of an Arch system
    /// (/usr/share/pacman/keyrings/archlinux, from archlinux-keyring) or of
    /// a package file you have checked.
    Init {
        /// The keyring files' path without suffix, e.g.
        /// /usr/share/pacman/keyrings/archlinux.
        #[arg(env = "SKL_KEYRING", value_name = "PREFIX")]
        prefix: PathBuf,
    },
    /// Update the keyring from the archlinux-keyring package of a repo.
    ///
    /// The package is verified with the store's keyring, as builds verify
    /// packages, and taken from the first repo that has it. Versions older
    /// than the one the keyring is from are refused.
    Update {
        /// Download the databases of the repos first, as `skl arch sync`
        /// does.
        #[arg(long)]
        sync: bool,
        /// Download the package if it isn't in the store yet.
        #[arg(long)]
        fetch: bool,
        /// Repo to take the package from (repeatable, in priority order),
        /// as for `skl arch build`.
        #[arg(long = "repo", value_name = "REPO", required = true)]
        repos: Vec<String>,
    },
    /// Show where the store's keyring is from.
    Show,
}

/// Run `skl arch`.
pub(crate) fn run(
    args: ArchArgs,
    workers: &Workers,
    store: &Store,
    jobs: NonZeroUsize,
) -> Result<()> {
    match args.command {
        ArchCommand::Import { packages } => {
            let packages = packages
                .iter()
                .map(|arg| local_package(arg))
                .collect::<Result<Vec<_>>>()?;
            with_verifier(workers, store, jobs, |verifier| {
                let ctx = context(workers, store, verifier, jobs);
                packages::import_local(&ctx, packages)
            })?;
        }
        ArchCommand::Build {
            output,
            sync: sync_first,
            fetch,
            rerun_scripts,
            repos,
            packages,
        } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let (parent, name) = open_parent(&output)?;
            let repos = repos
                .iter()
                .map(|r| repo_id(r))
                .collect::<Result<Vec<_>>>()?;
            let targets = packages
                .iter()
                .map(|arg| parse_target(arg, &repos))
                .collect::<Result<Vec<_>>>()?;
            let sources = load_sources(workers, store, &repos, sync_first, jobs)?;
            let chosen = packages::choose(&sources, &targets)?;
            eprintln!(
                "resolved {} packages ({} requested)",
                chosen.len(),
                targets.len()
            );
            let packages = match packages::all_local(&chosen) {
                Some(packages) => packages,
                None => with_verifier(workers, store, jobs, |verifier| {
                    let ctx = context(workers, store, verifier, jobs);
                    packages::get_packages(&ctx, &chosen, fetch)
                })?,
            };
            let built = scripts::build(
                workers,
                store,
                &packages,
                parent.as_fd(),
                name,
                rerun_scripts,
            )
            .with_context(|| format!("building {}", output.display()))?;
            let r = built.report;
            eprintln!(
                "built {}: {} files, {} dirs, {} symlinks, {} hard links",
                output.display(),
                r.files,
                r.dirs,
                r.symlinks,
                r.hardlinks
            );
            if r.chown_failures > 0 {
                eprintln!(
                    "warning: could not set owner of {} entries (try running as root or in a user namespace)",
                    r.chown_failures
                );
            }
            if r.xattr_failures > 0 {
                eprintln!("warning: could not set {} xattrs", r.xattr_failures);
            }
            report_code(&built.code);
        }
        ArchCommand::Local {
            command: LocalCommand::List,
        } => {
            for entry in packages::list_local(store)? {
                let Imported { id, package } = &entry.imported;
                println!("{}\t{}\t{id}", package.name, package.version);
            }
        }
        ArchCommand::Local {
            command: LocalCommand::Remove { packages },
        } => {
            let selectors = packages
                .iter()
                .map(|arg| parse_selector(arg))
                .collect::<Result<Vec<_>>>()?;
            let removed = packages::remove_local(store, &selectors)?;
            for entry in &removed.entries {
                let package = &entry.imported.package;
                eprintln!("removed {} {}", package.name, package.version);
            }
            for name in &removed.downloads {
                eprintln!("removed download {LOCAL}/{name}");
            }
            eprintln!("`skl gc` removes their contents from the store");
        }
        ArchCommand::Repo {
            command: RepoCommand::Add { name, server, db },
        } => repo::add(store, &name, &server, db.as_deref())?,
        ArchCommand::Repo {
            command: RepoCommand::List,
        } => {
            for id in repo::list(store)? {
                let config: repo::Config = store.repo_config(&id)?;
                let name = skladiste::repo::split_id(&id)?.1;
                let synced = match store.latest_sync(&id)? {
                    Some(record) => record.fetched,
                    None => "never synced".to_owned(),
                };
                println!("{name}\t{}\t{}\t{synced}", config.db, config.server);
            }
        }
        ArchCommand::Keyring { command } => run_keyring(command, workers, store, jobs)?,
        ArchCommand::Sync { repos } => {
            let repos = repos
                .iter()
                .map(|r| repo_id(r))
                .collect::<Result<Vec<_>>>()?;
            sync(workers, store, repos, jobs)?;
        }
    }
    Ok(())
}

/// Run `skl arch keyring`.
fn run_keyring(
    command: KeyringCommand,
    workers: &Workers,
    store: &Store,
    jobs: NonZeroUsize,
) -> Result<()> {
    let outcome = match command {
        KeyringCommand::Init { prefix } => {
            let open = |suffix| {
                let path = with_suffix(&prefix, suffix);
                File::open(&path).with_context(|| format!("opening {}", path.display()))
            };
            let files = KeyringFiles {
                certs: open(".gpg")?,
                trusted: open("-trusted")?,
                revoked: open("-revoked")?,
            };
            keyring::init(workers, store, files)
                .with_context(|| format!("setting the keyring {}", prefix.display()))?
        }
        KeyringCommand::Update { sync, fetch, repos } => {
            let repos = repos
                .iter()
                .map(|r| repo_id(r))
                .collect::<Result<Vec<_>>>()?;
            let sources = load_sources(workers, store, &repos, sync, jobs)?;
            let chosen = packages::find(&sources, keyring::PACKAGE)?;
            let id = match &chosen {
                Chosen::Local(pkg) => pkg.id,
                Chosen::Repo(_) => with_verifier(workers, store, jobs, |verifier| {
                    let ctx = context(workers, store, verifier, jobs);
                    packages::get_packages(&ctx, std::slice::from_ref(&chosen), fetch)
                })?[0],
            };
            keyring::update(workers, store, &id)?
        }
        KeyringCommand::Show => {
            match keyring::current(store)? {
                Some((id, record)) => {
                    println!("{id}\t{}\t{}", describe(&record), record.added);
                }
                None => println!("no keyring"),
            }
            return Ok(());
        }
    };
    match outcome {
        Outcome::Unchanged(record) => {
            eprintln!("the keyring is already {}", describe(&record));
        }
        Outcome::Set { old, new } => match old {
            Some(old) => eprintln!(
                "the keyring is now {} (was {})",
                describe(&new),
                describe(&old)
            ),
            None => eprintln!("the keyring is now {}", describe(&new)),
        },
    }
    Ok(())
}

/// Where the keyring `record` is from, for messages: `archlinux-keyring
/// VERSION`, or `from files`.
fn describe(record: &Record) -> String {
    match &record.package {
        Some(p) => format!("{} {}", keyring::PACKAGE, p.version),
        None => "from files".to_owned(),
    }
}

/// Load what `repos` (ids) offer, syncing those other than `@local`
/// first if `sync_first`, and say which versions are used.
fn load_sources(
    workers: &Workers,
    store: &Store,
    repos: &[String],
    sync_first: bool,
    jobs: NonZeroUsize,
) -> Result<Vec<Source>> {
    let synced: Vec<String> = repos.iter().filter(|r| *r != LOCAL).cloned().collect();
    if sync_first && !synced.is_empty() {
        sync(workers, store, synced, jobs)?;
    }
    let sources = packages::load_sources(workers, store, repos, jobs)?;
    for source in &sources {
        match source {
            Source::Local(pkgs) => {
                eprintln!("using {LOCAL} ({} imported packages)", pkgs.len());
            }
            Source::Synced(s) => eprintln!(
                "using {} as synced at {} ({} packages)",
                s.repo,
                s.record.fetched,
                s.entries.len()
            ),
        }
    }
    Ok(sources)
}

/// Report what a build did about package code.
fn report_code(code: &Code) {
    match code {
        Code::None => {}
        Code::Reused(id) => eprintln!(
            "installed what install scripts and hooks changed in an earlier build ({id}); \
             use --rerun-scripts to run them again"
        ),
        Code::Ran(ran) => {
            let (added, modified, removed) = ran.changes;
            eprintln!(
                "ran {} install scripts and {} hooks: {added} added, {modified} modified, \
                 {removed} removed; {} new blobs ({:.1} MiB)",
                ran.scripts,
                ran.hooks,
                ran.stats.new_blobs,
                mib(ran.stats.new_bytes)
            );
            if !ran.status.success() {
                eprintln!(
                    "warning: package code failed (see above); its changes are in the image, \
                     but a build of the same packages will run it again"
                );
            }
            if ran.snapshot_removal == skladiste::btrfs::Removal::EntryByEntry {
                eprintln!("{}", super::snapshot_hint());
            }
        }
    }
}

/// The directory `path` is in, opened, and the last component of `path`.
fn open_parent(path: &Path) -> Result<(OwnedFd, &OsStr)> {
    let name = path
        .file_name()
        .with_context(|| format!("{} does not end in a file name", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {}", parent.display()))?;
    Ok((dir, name))
}

/// Sync the repos with ids `repos` (all if empty), see [`repo::sync`].
fn sync(workers: &Workers, store: &Store, repos: Vec<String>, jobs: NonZeroUsize) -> Result<()> {
    for synced in repo::sync(workers, store, repos, jobs)? {
        match synced.packages {
            Some(packages) => eprintln!(
                "synced {}: {packages} packages ({:.1} MiB)",
                synced.repo,
                mib(synced.record.size)
            ),
            None => eprintln!(
                "{} is up to date (synced at {})",
                synced.repo, synced.record.fetched
            ),
        }
    }
    Ok(())
}

/// The context for importing packages, which reports on stderr.
fn context<'a, 'v>(
    workers: &'a Workers,
    store: &'a Store,
    verifier: &'a Verifier<'v>,
    jobs: NonZeroUsize,
) -> Context<'a, 'v> {
    Context {
        workers,
        store,
        verifier,
        jobs,
        report: &report,
    }
}

fn report(event: Event) {
    match event {
        Event::Downloaded { repo, name, size } => {
            eprintln!("downloaded {repo}/{name} ({:.1} MiB)", mib(size));
        }
        Event::Imported { package, stats } => eprintln!(
            "imported {} {}: {} files, {} new blobs ({:.1} MiB)",
            package.name,
            package.version,
            stats.files,
            stats.new_blobs,
            mib(stats.new_bytes)
        ),
        Event::AlreadyImported(package) => {
            eprintln!("{} {} was already imported", package.name, package.version);
        }
    }
}

/// A package argument of `import`: a URL, or a file whose signature is
/// in the file next to it with `.sig` appended. Files are opened when
/// their import begins.
fn local_package(arg: &OsString) -> Result<LocalPackage<'static>> {
    if let Some(s) = arg.to_str()
        && Url::is_url(s)
    {
        return Ok(LocalPackage::Url(Url::parse(s)?));
    }
    let path = PathBuf::from(arg);
    let size = path.metadata().map_or(0, |m| m.len());
    Ok(LocalPackage::File(LocalFile {
        name: path.display().to_string(),
        size,
        open: Box::new(move || {
            let open = |path: &Path| {
                File::open(path).with_context(|| format!("opening {}", path.display()))
            };
            Ok((open(&path)?, open(&with_suffix(&path, ".sig"))?))
        }),
    }))
}

/// Read a package argument of `build`: `NAME`, or `REPO/NAME` where `REPO`
/// (a name or an id, see [`repo_id`]) is one of `repos` (ids).
fn parse_target(arg: &str, repos: &[String]) -> Result<Target> {
    let (repo, name) = match arg.rsplit_once('/') {
        Some((repo, name)) => (Some(repo_id(repo)), name),
        None => (None, arg),
    };
    ensure!(
        repo::check_name(name).is_ok() && repo.as_ref().is_none_or(Result::is_ok),
        "{arg:?} is not NAME or REPO/NAME (to build with package files, \
         import them with `skl arch import` and use --repo @local)"
    );
    let repo = repo
        .map(|repo| {
            let repo = repo?;
            repos
                .iter()
                .position(|r| *r == repo)
                .with_context(|| format!("{arg}: repo {repo} is not among --repo"))
        })
        .transpose()?;
    Ok(Target {
        name: name.to_owned(),
        repo,
    })
}

/// Read a package argument of `local remove`: `NAME` or `NAME=VERSION`.
fn parse_selector(arg: &str) -> Result<packages::Selector> {
    let (name, version) = match arg.split_once('=') {
        Some((name, version)) => (name, Some(version)),
        None => (arg, None),
    };
    ensure!(
        repo::check_name(name).is_ok() && version.is_none_or(|v| !v.is_empty()),
        "{arg:?} is not NAME or NAME=VERSION"
    );
    Ok(packages::Selector {
        name: name.to_owned(),
        version: version.map(str::to_owned),
    })
}

/// Run `f` with a verifier that checks signatures with the store's
/// keyring, in up to `jobs` workers at once.
fn with_verifier<T>(
    workers: &Workers,
    store: &Store,
    jobs: NonZeroUsize,
    f: impl FnOnce(&Verifier) -> Result<T>,
) -> Result<T> {
    keyring::with_verifier(workers, store, jobs.get(), f).map_err(|e| {
        if e.is::<NoKeyring>() {
            anyhow!(
                "{e}; set one with `skl arch keyring init PREFIX` \
                 (e.g. /usr/share/pacman/keyrings/archlinux)"
            )
        } else if format!("{e:#}").contains("key not in the keyring") {
            anyhow!("{e:#}; if the keyring is outdated, `skl arch keyring update` updates it")
        } else {
            e
        }
    })
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(path);
    s.push(suffix);
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_arguments() {
        let repos = ["@arch/core".to_owned(), LOCAL.to_owned()];
        let parse = |s: &str| parse_target(s, &repos).map(|t| (t.repo, t.name));
        assert_eq!(parse("bash").unwrap(), (None, "bash".to_owned()));
        assert_eq!(parse("core/bash").unwrap(), (Some(0), "bash".to_owned()));
        assert_eq!(
            parse("@arch/core/bash").unwrap(),
            (Some(0), "bash".to_owned())
        );
        assert_eq!(parse("@local/bash").unwrap(), (Some(1), "bash".to_owned()));
        assert_eq!(
            parse("@arch/@local/bash").unwrap(),
            (Some(1), "bash".to_owned())
        );
        let e = parse("extra/bash").unwrap_err().to_string();
        assert!(e.contains("not among --repo"), "{e}");
        for bad in [
            "./bash-5.3-1-x86_64.pkg.tar.zst",
            "core/a/b",
            "/abs/path",
            "https://x/a.pkg.tar.zst",
            "",
        ] {
            let e = parse(bad).unwrap_err().to_string();
            assert!(e.contains("skl arch import"), "{e}");
        }
    }

    #[test]
    fn remove_arguments() {
        let parse = |s: &str| parse_selector(s).map(|s| s.to_string());
        assert_eq!(parse("bash").unwrap(), "bash");
        assert_eq!(parse("bash=1:5.3.3-1").unwrap(), "bash=1:5.3.3-1");
        for bad in ["", "=1", "bash=", "a/b", "./bash-5.3-1-x86_64.pkg.tar.zst"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
