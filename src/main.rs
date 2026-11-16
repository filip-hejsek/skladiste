use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use skladiste::arch;
use skladiste::arch::repo::{DbEntry, Snapshot};
use skladiste::arch::signature::{self, Keyring};
use skladiste::http::{RootCerts, Url};
use skladiste::install;
use skladiste::jobs::{default_jobs, par_map};
use skladiste::manifest::Package;
use skladiste::repo::LOCAL;
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
    /// Needed for importing packages.
    #[arg(long, env = "SKL_KEYRING", value_name = "PREFIX")]
    keyring: Option<PathBuf>,

    /// PEM file of root certificates to check HTTPS servers against,
    /// instead of the Mozilla roots built into skl (e.g. a CA bundle such
    /// as /etc/ssl/certs/ca-certificates.crt).
    #[arg(long, env = "SKL_CA_CERTS", value_name = "FILE")]
    ca_certs: Option<PathBuf>,

    /// Number of packages (or repo databases) to download and import at
    /// once [default: number of CPUs].
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
    /// Packages are names, files or http(s) URLs. A name is looked up in
    /// the repos given with `--repo`, or in one of them as `REPO/NAME`;
    /// the package's signature, size and SHA-256 come from the repo's
    /// database. Other arguments containing `/` or ending in
    /// `.pkg.tar.zst` are files (write `./REPO/NAME` for a file that would
    /// read as a name). The signature of a file or URL is read from the
    /// same path or URL with `.sig` appended. Downloads are kept in the
    /// store's `downloads/<repo>/` directory (`@local` for URLs) and not
    /// downloaded again for the same file name. Redirects are not
    /// followed.
    Import {
        #[command(flatten)]
        repos: Repos,
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
        #[command(flatten)]
        repos: Repos,
        /// Arch packages as for `import`, imported first if needed.
        #[arg(required = true)]
        packages: Vec<OsString>,
    },
    /// Manage repos.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Download the databases of repos.
    ///
    /// Every version is kept; builds use the latest. Repos synced together
    /// get their new versions only once all of them were downloaded and
    /// read.
    Sync {
        /// Repos to sync [default: all].
        repos: Vec<String>,
    },
}

#[derive(clap::Args)]
struct Repos {
    /// Repo to take packages given by name from (repeatable; the first
    /// repo that has a name wins). Each repo's latest sync is used.
    #[arg(long = "repo", value_name = "REPO")]
    repos: Vec<String>,
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
    /// List repos with the time of their latest sync.
    List,
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
    let store = Store::open(&cli.store)?;
    let jobs = cli.jobs.unwrap_or_else(default_jobs);
    let keyring = || -> Result<Keyring> {
        let prefix = cli
            .keyring
            .as_deref()
            .context("no keyring given (--keyring or SKL_KEYRING)")?;
        load_keyring(prefix)
    };
    match cli.command {
        Command::Import { repos, packages } => {
            let keyring = keyring()?;
            let ctx = Ctx {
                workers: &workers,
                store: &store,
                keyring: &keyring,
            };
            let sources = sources(&ctx, &packages, &repos.repos, jobs)?;
            get_packages(&ctx, &sources, jobs)?;
        }
        Command::Build {
            output,
            repos,
            packages,
        } => {
            if output.symlink_metadata().is_ok() {
                bail!("{} already exists", output.display());
            }
            let keyring = keyring()?;
            let ctx = Ctx {
                workers: &workers,
                store: &store,
                keyring: &keyring,
            };
            let sources = sources(&ctx, &packages, &repos.repos, jobs)?;
            let packages = get_packages(&ctx, &sources, jobs)?;
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
        Command::Repo {
            command: RepoCommand::Add { name, server, db },
        } => {
            let config = arch::repo::Config::new(&server, db.as_deref().unwrap_or(&name))?;
            store.add_repo(&name, &config)?;
        }
        Command::Repo {
            command: RepoCommand::List,
        } => {
            for name in store.repos()? {
                let config: arch::repo::Config = store.repo_config(&name)?;
                let synced = match store.latest_sync(&name)? {
                    Some(record) => record.fetched,
                    None => "never synced".to_owned(),
                };
                println!("{name}\t{}\t{}\t{synced}", config.db, config.server);
            }
        }
        Command::Sync { repos } => sync(&workers, &store, repos, jobs)?,
    }
    Ok(())
}

/// Download the databases of `repos` (all if empty), and record the new
/// versions once all of them were downloaded and read.
fn sync(workers: &Workers, store: &Store, repos: Vec<String>, jobs: NonZeroUsize) -> Result<()> {
    let repos = if repos.is_empty() {
        store.repos()?
    } else {
        repos
    };
    if repos.is_empty() {
        bail!("no repos (add one with `skl repo add`)");
    }
    let configs = repos
        .iter()
        .map(|name| store.repo_config(name))
        .collect::<Result<Vec<arch::repo::Config>>>()?;
    let synced = par_map(&configs, jobs, |config| {
        let record = arch::repo::fetch_db(workers, store, config)?;
        let entries = arch::repo::load_db(workers, store, &record)?;
        Ok((record, entries.len()))
    })?;
    for (name, (record, packages)) in repos.iter().zip(&synced) {
        store.save_sync(name, record)?;
        eprintln!(
            "synced {name}: {packages} packages ({:.1} MiB)",
            mib(record.size)
        );
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
    /// A package from a repo's latest snapshot, downloaded from `url`.
    Repo {
        repo: String,
        entry: Box<DbEntry>,
        url: Url,
    },
}

/// A package as given on the command line.
enum Arg {
    Source(Source),
    /// A package name, possibly qualified with a repo.
    Name {
        repo: Option<String>,
        name: String,
    },
}

/// Read a package argument: a URL stays a URL; `REPO/NAME` where `REPO`
/// is one of `repos` is a qualified name; anything else that contains `/`
/// or ends in `.pkg.tar.zst` is a path; the rest are names. `REPO/NAME`
/// where `REPO` is another of the `configured` repos is an error, as it is
/// more likely a mistake than a path.
fn parse_arg(arg: &OsString, repos: &[String], configured: &[String]) -> Result<Arg> {
    let Some(s) = arg.to_str() else {
        return Ok(Arg::Source(Source::Path(arg.into())));
    };
    if Url::is_url(s) {
        return Ok(Arg::Source(Source::Url(Url::parse(s)?)));
    }
    if !s.ends_with(".pkg.tar.zst") {
        if let Some((repo, name)) = s.split_once('/')
            && repos.iter().any(|r| r == repo)
            && !name.contains('/')
        {
            return Ok(Arg::Name {
                repo: Some(repo.to_owned()),
                name: name.to_owned(),
            });
        }
        if let Some((repo, name)) = s.split_once('/')
            && configured.iter().any(|r| r == repo)
            && !name.contains('/')
        {
            bail!("{s}: repo {repo} is not among --repo (write ./{s} for a file)");
        }
        if !s.contains('/') {
            return Ok(Arg::Name {
                repo: None,
                name: s.to_owned(),
            });
        }
    }
    Ok(Arg::Source(Source::Path(arg.into())))
}

/// Where to get each package in `args` from. Names are looked up in the
/// latest snapshots of `repos`, in order: the first repo that has the
/// name wins, unless the name is qualified.
fn sources(
    ctx: &Ctx,
    args: &[OsString],
    repos: &[String],
    jobs: NonZeroUsize,
) -> Result<Vec<Source>> {
    let configured = ctx.store.repos()?;
    let args = args
        .iter()
        .map(|arg| parse_arg(arg, repos, &configured))
        .collect::<Result<Vec<_>>>()?;
    let first_name = args.iter().find_map(|a| match a {
        Arg::Name { name, .. } => Some(name),
        Arg::Source(_) => None,
    });
    let snapshots = match first_name {
        None => Vec::new(),
        Some(name) if repos.is_empty() => {
            bail!("{name:?} is a package name, which needs repos to look in (--repo)")
        }
        Some(_) => load_snapshots(ctx, repos, jobs)?,
    };
    // A package named twice is taken once.
    let mut named = HashSet::new();
    let sources = args
        .into_iter()
        .map(|arg| match arg {
            Arg::Source(source) => Ok(Some(source)),
            Arg::Name { repo, name } => {
                let found = snapshots
                    .iter()
                    .filter(|s| repo.as_ref().is_none_or(|r| *r == s.repo))
                    .find_map(|s| Some((s, s.get(&name)?)));
                let Some((snapshot, entry)) = found else {
                    let repos = repo.map_or_else(|| repos.join(", "), |r| r.clone());
                    bail!("package {name} not found in {repos}");
                };
                ensure!(
                    entry.arch == arch::repo::ARCH || entry.arch == "any",
                    "package {}/{name} is for {}, not {}",
                    snapshot.repo,
                    entry.arch,
                    arch::repo::ARCH
                );
                if !named.insert((&snapshot.repo, &entry.name)) {
                    return Ok(None);
                }
                Ok(Some(Source::Repo {
                    repo: snapshot.repo.clone(),
                    url: snapshot.config.package_url(&entry.filename)?,
                    entry: Box::new(entry.clone()),
                }))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sources.into_iter().flatten().collect())
}

/// The latest snapshot of each of `repos`.
fn load_snapshots(ctx: &Ctx, repos: &[String], jobs: NonZeroUsize) -> Result<Vec<Snapshot>> {
    let snapshots = par_map(repos, jobs, |repo| {
        Snapshot::load(ctx.workers, ctx.store, repo)
    })?;
    for s in &snapshots {
        eprintln!(
            "using {} as synced at {} ({} packages)",
            s.repo,
            s.record.fetched,
            s.entries.len()
        );
    }
    Ok(snapshots)
}

/// [`get_package`] for each source, `jobs` at once, each import by its own
/// worker (so a compromised worker can't change another package's
/// manifest). Downloads start first, largest first (by the size in the
/// repo's database where known), then the largest archives, as they take
/// longest.
fn get_packages(ctx: &Ctx, sources: &[Source], jobs: NonZeroUsize) -> Result<Vec<Package>> {
    let downloaded = |repo: &str, name: &str| match ctx.store.open_download(repo, name) {
        Ok(Some(f)) => Some(f.metadata().map_or(0, |m| m.len())),
        _ => None,
    };
    let mut order: Vec<(usize, &Source, (bool, u64))> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let key = match source {
                Source::Path(p) => (false, p.metadata().map_or(0, |m| m.len())),
                Source::Url(url) => {
                    downloaded(LOCAL, url.file_name()).map_or((true, u64::MAX), |n| (false, n))
                }
                Source::Repo { repo, entry, .. } => {
                    downloaded(repo, &entry.filename).map_or((true, entry.csize), |n| (false, n))
                }
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
/// earlier downloads. Packages are identified by their repo and the hash
/// of the archive file. A package from a repo must have the SHA-256, name
/// and version that the repo's database gives. The file is opened once, so
/// the parsed content is the content that was verified and hashed, unless
/// the file is written to meanwhile (see planning/BUGS.md; only the
/// supervisor writes downloads). Concurrent calls for the same archive each
/// import it.
fn get_package(ctx: &Ctx, source: &Source) -> Result<Package> {
    let (mut file, what, repo, entry) = match source {
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
            (file, path.display().to_string(), LOCAL, None)
        }
        Source::Url(url) => (fetch(ctx, url)?, url.to_string(), LOCAL, None),
        Source::Repo { repo, entry, url } => (
            fetch_from_repo(ctx, repo, entry, url)?,
            format!("{repo}/{}", entry.filename),
            repo.as_str(),
            Some(entry),
        ),
    };
    file.seek(SeekFrom::Start(0))?;
    let mut sha256 = entry.map(|_| Sha256::new());
    let hash = hash_reader(Tee {
        inner: &mut file,
        sha256: sha256.as_mut(),
    })
    .with_context(|| format!("reading {what}"))?;
    if let (Some(entry), Some(sha256)) = (entry, sha256) {
        check_sha256(sha256, entry).with_context(|| format!("checking {what}"))?;
    }
    let pkg = match ctx.store.load_package(repo, &hash)? {
        Some(pkg) => pkg,
        None => {
            file.seek(SeekFrom::Start(0))?;
            let (pkg, stats) = ctx
                .workers
                .import_arch(ctx.store, file)
                .with_context(|| format!("importing {what}"))?;
            if let Some(entry) = entry {
                check_identity(&pkg, entry).with_context(|| format!("importing {what}"))?;
            }
            ctx.store.save_package(repo, &hash, &pkg)?;
            eprintln!(
                "imported {} {}: {} files, {} new objects ({:.1} MiB)",
                pkg.name,
                pkg.version,
                stats.files,
                stats.new_objects,
                mib(stats.new_bytes)
            );
            pkg
        }
    };
    if let Some(entry) = entry {
        check_identity(&pkg, entry).with_context(|| format!("checking {what}"))?;
    }
    Ok(pkg)
}

/// `.PKGINFO`'s name and version must be those of the database entry.
fn check_identity(pkg: &Package, entry: &DbEntry) -> Result<()> {
    ensure!(
        pkg.name == entry.name && pkg.version == entry.version,
        "the package is {} {}, but the repo's database says {} {}",
        pkg.name,
        pkg.version,
        entry.name,
        entry.version
    );
    Ok(())
}

fn check_sha256(sha256: Sha256, entry: &DbEntry) -> Result<()> {
    let actual = sha256.finalize();
    let expected = &entry.sha256;
    ensure!(
        hex(&actual).eq_ignore_ascii_case(expected),
        "SHA-256 is {}, but the repo's database says {expected}",
        hex(&actual)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Passes reads through, also hashing them with SHA-256 if wanted.
struct Tee<'a, R> {
    inner: R,
    sha256: Option<&'a mut Sha256>,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(h) = self.sha256.as_mut() {
            h.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Writes through, hashing with SHA-256.
struct Sha256Writer<W> {
    inner: W,
    sha256: Sha256,
}

impl<W: Write> Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha256.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The verified archive from `url`: downloaded earlier, or now. Only
/// verified downloads are kept, the archive first, so an archive whose
/// signature is there was complete.
fn fetch(ctx: &Ctx, url: &Url) -> Result<File> {
    let name = url.file_name();
    let sig_name = format!("{name}.sig");
    let store = ctx.store;
    if let Some(sig) = store.open_download(LOCAL, &sig_name)?
        && let Some(mut file) = store.open_download(LOCAL, name)?
    {
        let sig = read_signature(sig).with_context(|| format!("reading downloaded {sig_name}"))?;
        verify(ctx.keyring, &sig, &mut file).with_context(|| {
            format!("verifying {name}, downloaded earlier (delete downloads/{LOCAL}/{name} in the store to download it again)")
        })?;
        return Ok(file);
    }
    let sig_url = url.with_suffix(".sig");
    let mut sig = Vec::new();
    ctx.workers
        .download(&sig_url, &mut sig, signature::MAX_SIGNATURE_SIZE)
        .with_context(|| format!("downloading {sig_url}"))?;
    download_package(ctx, LOCAL, name, url, &sig, None)
}

/// The verified archive of a package in a repo: downloaded earlier, or
/// now. The signature, size and SHA-256 come from the repo's database.
fn fetch_from_repo(ctx: &Ctx, repo: &str, entry: &DbEntry, url: &Url) -> Result<File> {
    let name = &entry.filename;
    let sig = entry
        .pgpsig
        .as_deref()
        .with_context(|| format!("{repo}/{name} has no signature in the repo's database"))?;
    if let Some(mut file) = ctx.store.open_download(repo, name)? {
        verify(ctx.keyring, sig, &mut file).with_context(|| {
            format!("verifying {name}, downloaded earlier (delete downloads/{repo}/{name} in the store to download it again)")
        })?;
        return Ok(file);
    }
    download_package(ctx, repo, name, url, sig, Some(entry))
}

/// Download `url` and keep it as `name` in `repo`'s downloads if `sig`
/// verifies, with the signature next to it (`.sig`), written after the
/// archive. With `entry`, the size and SHA-256 must be those it gives.
fn download_package(
    ctx: &Ctx,
    repo: &str,
    name: &str,
    url: &Url,
    sig: &[u8],
    entry: Option<&DbEntry>,
) -> Result<File> {
    let store = ctx.store;
    let mut tmp = store.tmp_file()?;
    let max_size = entry.map_or(u64::MAX, |e| e.csize);
    let (size, sha256) = {
        let mut w = Sha256Writer {
            inner: BufWriter::with_capacity(64 << 10, tmp.file()),
            sha256: Sha256::new(),
        };
        let size = ctx
            .workers
            .download(url, &mut w, max_size)
            .and_then(|d| Ok(w.flush().map(|()| d.size)?))
            .with_context(|| format!("downloading {url}"))?;
        (size, w.sha256)
    };
    if let Some(entry) = entry {
        ensure!(
            size == entry.csize,
            "{url} has {size} bytes, but the repo's database says {}",
            entry.csize
        );
        check_sha256(sha256, entry).with_context(|| format!("downloading {url}"))?;
    }
    verify(ctx.keyring, sig, tmp.file()).with_context(|| format!("verifying {url}"))?;
    let file = tmp.save_download(repo, name)?;
    let sig_name = format!("{name}.sig");
    let mut sig_tmp = store.tmp_file()?;
    sig_tmp
        .file()
        .write_all(sig)
        .with_context(|| format!("writing {sig_name}"))?;
    sig_tmp.save_download(repo, &sig_name)?;
    eprintln!("downloaded {repo}/{name} ({:.1} MiB)", mib(size));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_arguments() {
        let repos = ["core".to_owned(), "extra".to_owned()];
        let configured = ["core".to_owned(), "extra".to_owned(), "multilib".to_owned()];
        let parse = |s: &str| parse_arg(&s.into(), &repos, &configured);
        let name = |s: &str| match parse(s).unwrap() {
            Arg::Name { repo, name } => (repo, name),
            Arg::Source(_) => panic!("{s} is not a name"),
        };
        let path = |s: &str| match parse(s).unwrap() {
            Arg::Source(Source::Path(p)) => p,
            _ => panic!("{s} is not a path"),
        };
        assert_eq!(name("bash"), (None, "bash".to_owned()));
        assert_eq!(
            name("extra/bash"),
            (Some("extra".to_owned()), "bash".to_owned())
        );
        assert_eq!(path("./core/bash"), Path::new("./core/bash"));
        assert_eq!(path("core/a/b"), Path::new("core/a/b"));
        assert_eq!(path("other/bash"), Path::new("other/bash"));
        assert_eq!(
            path("bash-5.3-1-x86_64.pkg.tar.zst"),
            Path::new("bash-5.3-1-x86_64.pkg.tar.zst")
        );
        assert_eq!(
            path("core/bash-5.3-1-x86_64.pkg.tar.zst"),
            Path::new("core/bash-5.3-1-x86_64.pkg.tar.zst")
        );
        assert!(matches!(
            parse("https://x/a.pkg.tar.zst"),
            Ok(Arg::Source(Source::Url(_)))
        ));
        let e = parse("multilib/bash").err().unwrap().to_string();
        assert!(e.contains("not among --repo"), "{e}");
    }
}
