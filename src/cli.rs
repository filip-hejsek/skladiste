//! The CLI: global options and core commands, and helpers shared by
//! commands. Commands of a frontend are in submodules (e.g. [`arch`]).

use std::ffi::OsString;
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, ensure};
use clap::{Parser, Subcommand};

use skladiste::btrfs;
use skladiste::diff::Change;
use skladiste::http::RootCerts;
use skladiste::jobs::default_jobs;
use skladiste::store::{NotAStore, Store, VersionProblem, WrongVersion};
use skladiste::worker::Workers;

pub(crate) mod arch;

#[derive(Parser)]
#[command(name = "skl", about = "Content-addressed package manager on btrfs")]
pub(crate) struct Cli {
    /// Store directory (must be on the same btrfs filesystem as images).
    #[arg(long, env = "SKL_STORE")]
    store: Option<PathBuf>,

    /// PEM file of root certificates to check HTTPS servers against,
    /// instead of the Mozilla roots built into skl (e.g. a CA bundle such
    /// as /etc/ssl/certs/ca-certificates.crt).
    #[arg(long, env = "SKL_CA_CERTS", value_name = "FILE")]
    ca_certs: Option<PathBuf>,

    /// Number of packages to import (or repo databases to read) at once,
    /// and of servers to download from at once [default: number of CPUs].
    #[arg(short, long, global = true)]
    jobs: Option<NonZeroUsize>,

    /// Run workers without new namespaces and bubblewrap (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_namespaces: bool,

    /// Run workers without Landlock (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_landlock: bool,

    /// Run workers without seccomp filters (INSECURE).
    #[cfg(feature = "insecure")]
    #[arg(long)]
    insecure_no_seccomp: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set up a store in the directory given with --store (or SKL_STORE),
    /// creating the directory if needed. Other commands need a store set
    /// up this way. In an existing store, it creates the parts of the
    /// layout that are missing.
    Init,
    /// Migrate the store to the format version this skl uses.
    ///
    /// Nothing else may use the store meanwhile. A development build of skl
    /// uses a development version of the format: migrating a store to it
    /// needs --dev, and afterwards only builds of that version can open the
    /// store. Snapshot the store first to keep a copy.
    Migrate {
        /// Allow migrating to a development version.
        #[arg(long)]
        dev: bool,
    },
    /// Arch Linux packages: repos, importing, and building images.
    Arch(arch::ArchArgs),
    /// Manage repos of all package formats.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Run a program in an image, as root, sandboxed with bubblewrap.
    ///
    /// The program sees only the image, read-write, with a read-only /proc
    /// (parts that show host-wide information hidden),
    /// basic devices in /dev, and empty tmpfs on /tmp and /run. It has no
    /// network and can't see host processes. When skl runs as root, the
    /// program keeps only the capabilities to change files' owners and
    /// permissions; otherwise it runs in a new user namespace that maps
    /// skl's uid and gid to root, and changing owners to other ids fails.
    /// The environment holds only PATH and PWD.
    ///
    /// Afterwards, prints what the program changed in the image (A added,
    /// M modified, D removed), found by comparing it with a snapshot taken
    /// before, and adds new file contents to the store. Changes to the
    /// image's root directory itself aren't shown. skl exits with the
    /// program's exit code.
    Run {
        /// The image: a subvolume made by `skl arch build`, on the same btrfs
        /// filesystem as the store.
        image: PathBuf,
        /// Program to run, searched in the image's PATH unless it contains
        /// a slash.
        program: OsString,
        /// Arguments of the program.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum RepoCommand {
    /// List repos by id (`@FORMAT/NAME`) with the time of their latest sync.
    List,
}

/// Run the command that `cli` gives.
pub(crate) fn run(cli: Cli) -> Result<ExitCode> {
    let mut workers = Workers::new("/proc/self/exe");
    #[cfg(feature = "insecure")]
    {
        if cli.insecure_no_namespaces {
            workers.disable_namespaces();
        }
        if cli.insecure_no_landlock {
            workers.disable_landlock();
        }
        if cli.insecure_no_seccomp {
            workers.disable_seccomp();
        }
    }
    if let Some(path) = &cli.ca_certs {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let roots = RootCerts::from_pem(&pem)
            .with_context(|| format!("loading root certificates from {}", path.display()))?;
        workers.set_root_certs(roots);
    }
    let store_path = cli
        .store
        .as_deref()
        .context("no store given (--store or SKL_STORE)")?;
    let store = || open_store(store_path);
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    match cli.command {
        Command::Init => {
            Store::init_path(store_path).map_err(migrate_hint)?;
        }
        Command::Migrate { dev } => {
            let migrated = Store::migrate_path(store_path, dev).map_err(migrate_hint)?;
            if migrated.from == migrated.to {
                println!("the store already has format version {}", migrated.to);
            } else {
                println!(
                    "migrated the store from format version {} to {}",
                    migrated.from, migrated.to
                );
            }
        }
        Command::Arch(args) => arch::run(args, &workers, &store()?, jobs)?,
        Command::Repo {
            command: RepoCommand::List,
        } => {
            let store = store()?;
            for id in store.repos()? {
                let synced = match store.latest_sync(&id)? {
                    Some(record) => record.fetched,
                    None => "never synced".to_owned(),
                };
                println!("{id}\t{synced}");
            }
        }
        Command::Run {
            image,
            program,
            args,
        } => return run_in_image(&workers, &store()?, &image, &program, &args),
    }
    Ok(ExitCode::SUCCESS)
}

/// The store at `path`, which `skl init` has set up.
fn open_store(path: &Path) -> Result<Store> {
    Store::open_path(path).map_err(|e| match e.downcast_ref::<NotAStore>() {
        Some(not) if not.can_init() => {
            anyhow!("{} is {not}; set one up with `skl init`", path.display())
        }
        Some(not) => anyhow!("{} is {not}", path.display()),
        None => migrate_hint(e),
    })
}

/// Suggest `skl migrate` for a store that needs it.
fn migrate_hint(e: anyhow::Error) -> anyhow::Error {
    let hint = match e.downcast_ref::<WrongVersion>().map(|w| w.problem) {
        Some(VersionProblem::NeedsMigration { to_dev: false }) => "run `skl migrate`",
        Some(VersionProblem::NeedsMigration { to_dev: true }) => {
            "to migrate it, snapshot it if you want to keep a copy, then run `skl migrate --dev`"
        }
        _ => return e,
    };
    anyhow!("{e:#}; {hint}")
}

/// `skl run`: run the program, then print what it changed.
fn run_in_image(
    workers: &Workers,
    store: &Store,
    image: &Path,
    program: &OsString,
    args: &[OsString],
) -> Result<ExitCode> {
    let dir = File::open(image).with_context(|| format!("opening {}", image.display()))?;
    ensure!(
        dir.metadata()?.is_dir(),
        "{} is not a directory",
        image.display()
    );
    let captured = skladiste::run::run_captured(workers, store, dir.as_fd(), program, args)?;
    let (mut added, mut modified, mut removed) = (0, 0, 0);
    for change in &captured.changes {
        let letter = match change {
            Change::Added(_) => {
                added += 1;
                'A'
            }
            Change::Modified(_) => {
                modified += 1;
                'M'
            }
            Change::Removed(_) => {
                removed += 1;
                'D'
            }
        };
        // Paths come from the image: escape control characters.
        eprintln!("{letter} /{}", change.path().escape_debug());
    }
    let stats = &captured.stats;
    eprintln!(
        "{added} added, {modified} modified, {removed} removed; {} new objects ({:.1} MiB)",
        stats.new_objects,
        mib(stats.new_bytes)
    );
    if captured.snapshot_removal == btrfs::Removal::EntryByEntry {
        eprintln!(
            "hint: without root, skl had to remove the snapshot it took entry by entry, which is \
             slow for large images; mounting the filesystem with {0} (e.g. `mount -o \
             remount,{0} MOUNTPOINT`) lets it remove the snapshot at once. Note that the option \
             lets any user remove a subvolume whose root directory they can write to, with all \
             its contents.",
            btrfs::USER_RM_OPTION
        );
    }
    let status = captured.status;
    let code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

pub(crate) fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
