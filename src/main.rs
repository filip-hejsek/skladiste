use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use skladiste::install;
use skladiste::jobs::{default_jobs, par_map};
use skladiste::manifest::Package;
use skladiste::store::{Store, hash_reader};
use skladiste::worker::{self, Workers};

#[derive(Parser)]
#[command(name = "skl", about = "Content-addressed package manager on btrfs")]
struct Cli {
    /// Store directory (must be on the same btrfs filesystem as images).
    #[arg(long, env = "SKL_STORE")]
    store: PathBuf,

    /// Number of packages to import at once [default: number of CPUs].
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
    /// Import Arch package files into the store.
    Import {
        #[arg(required = true)]
        packages: Vec<PathBuf>,
    },
    /// Create a new image subvolume containing the given packages.
    ///
    /// No dependency resolution is done and install scripts are not run.
    Build {
        /// Path of the new subvolume (must not exist).
        #[arg(short, long)]
        output: PathBuf,
        /// Arch package files (imported first if needed).
        #[arg(required = true)]
        packages: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == worker::SUBCOMMAND) {
        return worker::main(args);
    }
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    #[allow(unused_mut)]
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
    let store = Store::open(&cli.store)?;
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    let get_packages = |paths: &[PathBuf]| get_packages(&workers, &store, paths, jobs);
    match cli.command {
        Command::Import { packages } => {
            get_packages(&packages)?;
        }
        Command::Build { output, packages } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let packages = get_packages(&packages)?;
            let r = install::build(&workers, &store, &packages, &output)?;
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
        }
    }
    Ok(())
}

/// [`get_package`] for each path, `jobs` at once, each import by its own
/// worker (so a compromised worker can't change another package's
/// manifest). The largest archives start first, as they take longest.
fn get_packages(
    workers: &Workers,
    store: &Store,
    paths: &[PathBuf],
    jobs: NonZeroUsize,
) -> Result<Vec<Package>> {
    let mut order: Vec<(usize, &PathBuf, u64)> = paths
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p, p.metadata().map_or(0, |m| m.len())))
        .collect();
    order.sort_by_key(|&(_, _, size)| std::cmp::Reverse(size));
    let pkgs = par_map(&order, jobs, |&(i, p, _)| {
        Ok((i, get_package(workers, store, p)?))
    })?;
    let mut slots: Vec<Option<Package>> = vec![None; paths.len()];
    for (i, pkg) in pkgs {
        slots[i] = Some(pkg);
    }
    Ok(slots.into_iter().flatten().collect())
}

/// Load a package's manifest from the store, importing the archive if needed.
/// Packages are identified by the hash of the archive file. The file is
/// opened once, so the parsed content is the content that was hashed.
/// Concurrent calls for the same archive each import it.
fn get_package(workers: &Workers, store: &Store, path: &Path) -> Result<Package> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let id = hash_reader(&mut file)
        .with_context(|| format!("reading {}", path.display()))?
        .to_string();
    if let Some(pkg) = store.load_package(&id)? {
        return Ok(pkg);
    }
    file.seek(SeekFrom::Start(0))?;
    let (pkg, stats) = workers
        .import_arch(store, file)
        .with_context(|| format!("importing {}", path.display()))?;
    store.save_package(&id, &pkg)?;
    eprintln!(
        "imported {} {}: {} files, {} new objects ({:.1} MiB)",
        pkg.name,
        pkg.version,
        stats.files,
        stats.new_objects,
        stats.new_bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(pkg)
}
