use std::ffi::OsString;
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use skladiste::btrfs;
use skladiste::diff::Change;
use skladiste::http::RootCerts;
use skladiste::jobs::default_jobs;
use skladiste::store::Store;
use skladiste::worker::{self, Workers};

use cli::mib;

mod cli;

#[derive(Parser)]
#[command(name = "skl", about = "Content-addressed package manager on btrfs")]
struct Cli {
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
    /// Arch Linux packages: repos, importing, and building images.
    Arch(cli::arch::ArchArgs),
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

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == worker::SUBCOMMAND) {
        return worker::main(args);
    }
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
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
    let store = cli
        .store
        .as_deref()
        .context("no store given (--store or SKL_STORE)")?;
    let store = Store::open(store)?;
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    match cli.command {
        Command::Arch(args) => cli::arch::run(args, &workers, &store, jobs)?,
        Command::Run {
            image,
            program,
            args,
        } => return run_in_image(&workers, &store, &image, &program, &args),
    }
    Ok(ExitCode::SUCCESS)
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
