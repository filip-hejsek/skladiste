use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use skladiste::arch::signature::{self, Keyring};
use skladiste::http::Url;
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

    /// Arch keyring to verify package signatures with, as the path without
    /// suffix: PREFIX.gpg, PREFIX-trusted and PREFIX-revoked are read.
    #[arg(long, env = "SKL_KEYRING", value_name = "PREFIX")]
    keyring: PathBuf,

    /// Number of packages to download and import at once [default: number
    /// of CPUs].
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
    /// Import Arch packages into the store.
    ///
    /// Packages are files or http(s) URLs. Each package's signature is read
    /// from the same path or URL with `.sig` appended. Downloads are kept in
    /// the store's `downloads/` directory and not downloaded again from a
    /// URL with the same file name. Redirects are not followed.
    Import {
        #[arg(required = true)]
        packages: Vec<OsString>,
    },
    /// Create a new image subvolume containing the given packages.
    ///
    /// No dependency resolution is done and install scripts are not run.
    Build {
        /// Path of the new subvolume (must not exist).
        #[arg(short, long)]
        output: PathBuf,
        /// Arch packages as for `import`, imported first if needed.
        #[arg(required = true)]
        packages: Vec<OsString>,
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
    let keyring = load_keyring(&cli.keyring)?;
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    let ctx = Ctx {
        workers: &workers,
        store: &store,
        keyring: &keyring,
    };
    match cli.command {
        Command::Import { packages } => {
            get_packages(&ctx, &parse_sources(&packages)?, jobs)?;
        }
        Command::Build { output, packages } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let packages = get_packages(&ctx, &parse_sources(&packages)?, jobs)?;
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

struct Ctx<'a> {
    workers: &'a Workers,
    store: &'a Store,
    keyring: &'a Keyring,
}

/// Where a package comes from.
enum Source {
    Path(PathBuf),
    Url(Url),
}

fn parse_sources(args: &[OsString]) -> Result<Vec<Source>> {
    args.iter()
        .map(|arg| match arg.to_str() {
            Some(s) if Url::is_url(s) => Ok(Source::Url(Url::parse(s)?)),
            _ => Ok(Source::Path(arg.into())),
        })
        .collect()
}

/// [`get_package`] for each source, `jobs` at once, each import by its own
/// worker (so a compromised worker can't change another package's
/// manifest). Downloads start first, then the largest archives, as they
/// take longest.
fn get_packages(ctx: &Ctx, sources: &[Source], jobs: NonZeroUsize) -> Result<Vec<Package>> {
    let size = |path: &Path| path.metadata().map_or(0, |m| m.len());
    let mut order: Vec<(usize, &Source, u64)> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let key = match source {
                Source::Path(p) => size(p),
                Source::Url(url) => match ctx.store.open_download(url.file_name()) {
                    Ok(Some(f)) => f.metadata().map_or(0, |m| m.len()),
                    _ => u64::MAX,
                },
            };
            (i, source, key)
        })
        .collect();
    order.sort_by_key(|&(_, _, key)| std::cmp::Reverse(key));
    let pkgs = par_map(&order, jobs, |&(i, source, _)| {
        Ok((i, get_package(ctx, source)?))
    })?;
    let mut slots: Vec<Option<Package>> = vec![None; sources.len()];
    for (i, pkg) in pkgs {
        slots[i] = Some(pkg);
    }
    Ok(slots.into_iter().flatten().collect())
}

/// Load a package's manifest from the store, downloading and importing the
/// archive if needed. The signature is checked first, every time, also for
/// earlier downloads. Packages are identified by the hash of the archive
/// file. The file is opened once, so the parsed content is the content that
/// was verified and hashed, unless the file is written to meanwhile (see
/// planning/BUGS.md; only the supervisor writes downloads). Concurrent
/// calls for the same archive each import it.
fn get_package(ctx: &Ctx, source: &Source) -> Result<Package> {
    let (mut file, what) = match source {
        Source::Path(path) => {
            let mut file =
                File::open(path).with_context(|| format!("opening {}", path.display()))?;
            let sig_path = with_suffix(path, ".sig");
            let sig =
                File::open(&sig_path).with_context(|| format!("opening {}", sig_path.display()))?;
            let sig =
                read_signature(sig).with_context(|| format!("reading {}", sig_path.display()))?;
            verify(ctx.keyring, &sig, &mut file)
                .with_context(|| format!("verifying {}", path.display()))?;
            (file, path.display().to_string())
        }
        Source::Url(url) => (fetch(ctx, url)?, url.to_string()),
    };
    file.seek(SeekFrom::Start(0))?;
    let id = hash_reader(&mut file)
        .with_context(|| format!("reading {what}"))?
        .to_string();
    if let Some(pkg) = ctx.store.load_package(&id)? {
        return Ok(pkg);
    }
    file.seek(SeekFrom::Start(0))?;
    let (pkg, stats) = ctx
        .workers
        .import_arch(ctx.store, file)
        .with_context(|| format!("importing {what}"))?;
    ctx.store.save_package(&id, &pkg)?;
    eprintln!(
        "imported {} {}: {} files, {} new objects ({:.1} MiB)",
        pkg.name,
        pkg.version,
        stats.files,
        stats.new_objects,
        mib(stats.new_bytes)
    );
    Ok(pkg)
}

/// The verified archive from `url`: downloaded earlier, or now. Only
/// verified downloads are kept, the archive first, so an archive whose
/// signature is there was complete.
fn fetch(ctx: &Ctx, url: &Url) -> Result<File> {
    let name = url.file_name();
    let sig_name = format!("{name}.sig");
    let store = ctx.store;
    if let Some(sig) = store.open_download(&sig_name)?
        && let Some(mut file) = store.open_download(name)?
    {
        let sig = read_signature(sig).with_context(|| format!("reading downloaded {sig_name}"))?;
        verify(ctx.keyring, &sig, &mut file).with_context(|| {
            format!("verifying {name}, downloaded earlier (delete downloads/{name} in the store to download it again)")
        })?;
        return Ok(file);
    }
    let sig_url = url.with_suffix(".sig");
    let mut sig = Vec::new();
    ctx.workers
        .download(&sig_url, &mut sig, signature::MAX_SIGNATURE_SIZE)
        .with_context(|| format!("downloading {sig_url}"))?;
    let mut tmp = store.tmp_file()?;
    let mut w = BufWriter::with_capacity(64 << 10, tmp.file());
    let size = ctx
        .workers
        .download(url, &mut w, u64::MAX)
        .and_then(|size| Ok(w.flush().map(|()| size)?))
        .with_context(|| format!("downloading {url}"))?;
    drop(w);
    verify(ctx.keyring, &sig, tmp.file()).with_context(|| format!("verifying {url}"))?;
    let file = tmp.save_download(name)?;
    let mut sig_tmp = store.tmp_file()?;
    sig_tmp
        .file()
        .write_all(&sig)
        .with_context(|| format!("writing {sig_name}"))?;
    sig_tmp.save_download(&sig_name)?;
    eprintln!("downloaded {name} ({:.1} MiB)", mib(size));
    Ok(file)
}

/// Read a signature file, which must be at most
/// [`signature::MAX_SIGNATURE_SIZE`] bytes.
fn read_signature(file: File) -> Result<Vec<u8>> {
    let mut sig = Vec::new();
    file.take(signature::MAX_SIGNATURE_SIZE + 1)
        .read_to_end(&mut sig)?;
    if sig.len() as u64 > signature::MAX_SIGNATURE_SIZE {
        bail!("signature file is too large");
    }
    Ok(sig)
}

/// Check `file`'s signature from its start.
fn verify(keyring: &Keyring, sig: &[u8], file: &mut File) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    keyring.verify(sig, &*file)?;
    Ok(())
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Load the keyring `PREFIX.gpg`, `PREFIX-trusted`, `PREFIX-revoked`.
fn load_keyring(prefix: &Path) -> Result<Keyring> {
    let open = |suffix| {
        let path = with_suffix(prefix, suffix);
        File::open(&path)
            .map(BufReader::new)
            .with_context(|| format!("opening {}", path.display()))
    };
    Keyring::load(open(".gpg")?, open("-trusted")?, open("-revoked")?)
        .with_context(|| format!("loading keyring {}", prefix.display()))
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(path);
    s.push(suffix);
    s.into()
}
