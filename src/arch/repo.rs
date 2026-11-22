//! Arch repos: their configuration and databases (pacman's sync dbs).
//!
//! A repo's database (`core.db`) is a gzip-compressed tar archive with a
//! directory `NAME-VERSION/` per package, holding a `desc` file. Arch
//! doesn't sign its databases, so they are only as trustworthy as the
//! mirror that serves them; packages are signed.
//!
//! A database is untrusted input, so [`load_db`] reads it in a sandboxed
//! worker that can access only the database, and checks the result with
//! [`validate`].

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::arch::ArchSection;
use crate::arch::signature::MAX_SIGNATURE_SIZE;
use crate::download::{self, Downloaded, Request, Unless};
use crate::http::Url;
use crate::manifest::Package;
use crate::repo::{self, SyncRecord};
use crate::resolve::{Candidate, Dep, Op, Provide};
use crate::store::Store;
use crate::worker::{self, Workers};

pub(crate) mod read_db_worker;

/// Longest name, version, file name or dependency accepted.
const MAX_FIELD: usize = 256;

/// The architecture images are built for, as in pacman's `$arch`.
pub const ARCH: &str = "x86_64";

/// Largest database accepted (`extra.db` is about 8 MiB).
pub const MAX_DB_SIZE: u64 = 64 << 20;

/// The package format's name: Arch repos have the ids `@arch/NAME` (see
/// [`repo::id`]).
pub const FORMAT: &str = "arch";

/// The id of the pseudo-repo of Arch packages imported from files or URLs.
pub const LOCAL_REPO: &str = "@arch/@local";

/// The id of the Arch repo given as `NAME` (a repo name or
/// [`repo::LOCAL`]) or as its id `@arch/NAME`.
pub fn repo_id(arg: &str) -> Result<String> {
    let prefix = format!("@{FORMAT}/");
    repo::id(FORMAT, arg.strip_prefix(&prefix).unwrap_or(arg))
}

/// Configuration of an Arch repo, kept in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the repo's files are, in order of preference: mirrors, each
    /// in the format of pacman's `Server`, where `$repo` stands for
    /// [`Config::db`] and `$arch` for [`ARCH`]. At least one.
    pub servers: Vec<String>,
    /// Name of the database on the server: `core` for `core.db`.
    pub db: String,
}

/// Most servers a repo may have.
pub const MAX_SERVERS: usize = 64;

impl Config {
    /// Check that `db` is a plain name and that `servers` (at least one, at
    /// most [`MAX_SERVERS`], none twice) give valid URLs.
    pub fn new(servers: &[String], db: &str) -> Result<Config> {
        repo::check_name(db).context("bad database name")?;
        ensure!(!servers.is_empty(), "a repo needs a server");
        ensure!(
            servers.len() <= MAX_SERVERS,
            "{} servers are too many (at most {MAX_SERVERS})",
            servers.len()
        );
        let config = Config {
            servers: servers.to_vec(),
            db: db.to_owned(),
        };
        let urls = config.db_urls()?;
        for (i, url) in urls.iter().enumerate() {
            ensure!(
                !urls[..i].contains(url),
                "server {} is given twice",
                servers[i]
            );
        }
        Ok(config)
    }

    /// The servers with `$repo` and `$arch` replaced.
    fn bases(&self) -> impl Iterator<Item = String> {
        self.servers.iter().map(|server| {
            let base = server.replace("$repo", &self.db).replace("$arch", ARCH);
            base.trim_end_matches('/').to_owned()
        })
    }

    /// URLs of the database, `<server>/<db>.db`, one per server.
    pub fn db_urls(&self) -> Result<Vec<Url>> {
        let name = format!("{}.db", self.db);
        self.bases()
            .map(|base| Url::parse(&format!("{base}/{name}")))
            .collect()
    }

    /// URLs of a package file, `<server>/<file name>`, one per server.
    pub fn package_urls(&self, file_name: &str) -> Result<Vec<Url>> {
        self.bases()
            .map(|base| Url::parse(&format!("{base}/{file_name}")))
            .collect()
    }
}

/// The servers of a pacman mirror list (as `/etc/pacman.d/mirrorlist`), in
/// their order: the values of its `Server = URL` lines. Blank lines and
/// comments (`#`) are skipped; anything else is an error.
pub fn parse_mirrorlist(text: &str) -> Result<Vec<String>> {
    let mut servers = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let server = line
            .split_once('=')
            .filter(|(key, _)| key.trim_end() == "Server")
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty());
        match server {
            Some(server) => servers.push(server.to_owned()),
            None => bail!("line {}: not `Server = URL`: {line:?}", n + 1),
        }
    }
    Ok(servers)
}

/// Add the Arch repo `name` with `servers` (see [`Config::servers`]) and the
/// database `db` (see [`Config::db`]; `name` if `None`).
pub fn add(store: &Store, name: &str, servers: &[String], db: Option<&str>) -> Result<()> {
    repo::check_name(name)?;
    let config = Config::new(servers, db.unwrap_or(name))?;
    store.add_repo(&repo_id(name)?, &config)
}

/// Replace the servers of the Arch repo with id `repo`. Its snapshots stay:
/// mirrors serve the same files.
pub fn set_servers(store: &Store, repo: &str, servers: &[String]) -> Result<()> {
    let config: Config = store.repo_config(repo)?;
    let config = Config::new(servers, &config.db)?;
    store.set_repo_config(repo, &config)
}

/// The ids of the configured Arch repos, sorted.
pub fn list(store: &Store) -> Result<Vec<String>> {
    let mut ids = store.repos()?;
    ids.retain(|id| repo::split_id(id).is_ok_and(|(f, _)| f == FORMAT));
    Ok(ids)
}

/// A repo after [`sync`].
pub struct Synced {
    /// The repo's id.
    pub repo: String,
    /// Its latest record: the one just written, or the one before if the
    /// database didn't change.
    pub record: SyncRecord,
    /// Number of packages in the database, if it is a new version.
    pub packages: Option<usize>,
}

/// Download the databases of the repos with ids `repos` (all Arch repos if
/// empty), up to `jobs` at once, and record the new versions once all of
/// them were downloaded and read. A database that the server still has
/// as last synced isn't downloaded again, and gets no new record. Returns
/// the repos in the order of `repos`.
pub fn sync(
    workers: &Workers,
    store: &Store,
    repos: Vec<String>,
    jobs: NonZeroUsize,
) -> Result<Vec<Synced>> {
    let repos = if repos.is_empty() {
        list(store)?
    } else {
        repos
    };
    if repos.is_empty() {
        bail!("no repos (add one with `skl arch repo add`)");
    }
    let mut latest = Vec::new();
    let mut requests = Vec::new();
    for name in &repos {
        let config: Config = store.repo_config(name)?;
        let record = store.latest_sync(name)?;
        requests.push(db_request(&config, record.as_ref())?);
        latest.push(record);
    }
    let mut synced = download::fetch_and_run(
        workers,
        jobs,
        Vec::new(),
        requests,
        |i, data, downloaded| {
            if downloaded.not_modified {
                return Ok(Some((i, None)));
            }
            let record = db_record(store, &data, downloaded)?;
            Ok(Some((i, Some(record))))
        },
        |(i, record)| {
            let Some(record) = record else {
                return Ok((i, None));
            };
            let entries = load_db(workers, store, &record)?;
            Ok((i, Some((record, entries.len()))))
        },
    )?;
    synced.sort_by_key(|&(i, _)| i);
    synced
        .into_iter()
        .map(|(i, new)| {
            let (record, packages) = match new {
                Some((record, packages)) => {
                    store.save_sync(&repos[i], &record)?;
                    (record, Some(packages))
                }
                None => {
                    let record = latest[i].take();
                    (
                        record.context("server said that a database didn't change")?,
                        None,
                    )
                }
            };
            Ok(Synced {
                repo: repos[i].clone(),
                record,
                packages,
            })
        })
        .collect()
}

/// A repo's latest snapshot: its database as last synced.
pub struct Snapshot {
    pub repo: String,
    pub config: Config,
    pub record: SyncRecord,
    pub entries: Vec<DbEntry>,
}

impl Snapshot {
    /// Load the latest snapshot of `repo`, which must have been synced.
    pub fn load(workers: &Workers, store: &Store, repo: &str) -> Result<Snapshot> {
        let config: Config = store.repo_config(repo)?;
        let record = store.latest_sync(repo)?.with_context(|| {
            format!("repo {repo} was never synced (run `skl arch sync {repo}`)")
        })?;
        let entries = load_db(workers, store, &record)?;
        Ok(Snapshot {
            repo: repo.to_owned(),
            config,
            record,
            entries,
        })
    }

    /// The entries for dependency resolution, in the same order.
    pub fn candidates(&self) -> Result<Vec<Candidate>> {
        self.entries
            .iter()
            .map(|e| e.candidate())
            .collect::<Result<_>>()
            .with_context(|| format!("in repo {}", self.repo))
    }
}

impl DbEntry {
    /// This package for dependency resolution.
    pub fn candidate(&self) -> Result<Candidate> {
        candidate(
            &self.name,
            &self.version,
            &self.depends,
            &self.provides,
            &self.conflicts,
        )
    }
}

/// An imported package for dependency resolution, by its own metadata
/// (`.PKGINFO`). That came from the import worker, so the name and
/// version are checked here as well as the dependencies.
pub fn package_candidate<F>(pkg: &Package<F>) -> Result<Candidate> {
    check_name(&pkg.name)?;
    check_version(&pkg.version).with_context(|| format!("package {}", pkg.name))?;
    let section = ArchSection::of(pkg)?;
    candidate(
        &pkg.name,
        &pkg.version,
        &section.depends,
        &section.provides,
        &section.conflicts,
    )
}

fn candidate(
    name: &str,
    version: &str,
    depends: &[String],
    provides: &[String],
    conflicts: &[String],
) -> Result<Candidate> {
    let deps = |list: &[String]| list.iter().map(|d| parse_dep(d)).collect::<Result<_>>();
    Ok::<_, anyhow::Error>(Candidate {
        name: name.to_owned(),
        version: version.to_owned(),
        depends: deps(depends)?,
        provides: provides
            .iter()
            .map(|p| parse_provide(p))
            .collect::<Result<_>>()?,
        conflicts: deps(conflicts)?,
    })
    .with_context(|| format!("package {name}"))
}

/// Parse a dependency or conflict: `NAME`, or `NAME` followed by `<`,
/// `<=`, `=`, `>=` or `>` and a version.
pub fn parse_dep(s: &str) -> Result<Dep> {
    let Some(at) = s.find(['<', '>', '=']) else {
        check_name(s)?;
        return Ok(Dep {
            name: s.to_owned(),
            version: None,
        });
    };
    let (name, rest) = s.split_at(at);
    let (op, version) = [
        ("<=", Op::Le),
        (">=", Op::Ge),
        ("<", Op::Lt),
        (">", Op::Gt),
        ("=", Op::Eq),
    ]
    .into_iter()
    .find_map(|(text, op)| Some((op, rest.strip_prefix(text)?)))
    .with_context(|| format!("bad dependency {s:?}"))?;
    check_name(name)?;
    check_dep_version(version).with_context(|| format!("bad dependency {s:?}"))?;
    Ok(Dep {
        name: name.to_owned(),
        version: Some((op, version.to_owned())),
    })
}

/// Parse a provide: `NAME` or `NAME=VERSION`.
pub fn parse_provide(s: &str) -> Result<Provide> {
    let dep = parse_dep(s)?;
    match dep.version {
        None => Ok(Provide {
            name: dep.name,
            version: None,
        }),
        Some((Op::Eq, version)) => Ok(Provide {
            name: dep.name,
            version: Some(version),
        }),
        Some(_) => bail!("bad provide {s:?} (only = is allowed)"),
    }
}

/// A version in a dependency, where the release and epoch are optional.
fn check_dep_version(version: &str) -> Result<()> {
    ensure!(
        !version.is_empty()
            && version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+~:-".contains(&b)),
        "bad version {version:?}"
    );
    Ok(())
}

/// A request for the database of the repo with `config`, to hold in
/// memory, from the first of its servers that has it. Databases aren't
/// signed, so if one changes on the server while it is downloaded, the
/// new one is as good. With `latest`, the repo's latest record, the
/// database is downloaded only if the server has another version than
/// that one, if the record has a validator and the database is
/// requested from the URL the record names.
pub fn db_request(config: &Config, latest: Option<&SyncRecord>) -> Result<Request<Vec<u8>>> {
    let urls = config.db_urls()?;
    let unless = latest.and_then(|record| {
        Some(Unless {
            url: urls
                .iter()
                .find(|url| url.to_string() == record.url)?
                .clone(),
            validator: record.validator.clone()?,
        })
    });
    Ok(Request {
        urls,
        max_size: MAX_DB_SIZE,
        restart_if_changed: true,
        unless,
        sink: Vec::new(),
    })
}

/// Add the database `data`, downloaded just now, to the store, and return a
/// record of it to save once it has been checked.
pub fn db_record(store: &Store, mut data: &[u8], downloaded: Downloaded) -> Result<SyncRecord> {
    let fetched = repo::timestamp(SystemTime::now());
    let added = store.add_blob(&mut data)?;
    Ok(SyncRecord {
        hash: added.hash,
        size: added.size,
        url: downloaded.url.to_string(),
        fetched,
        last_modified: downloaded.last_modified,
        etag: downloaded.etag,
        validator: downloaded.validator,
    })
}

/// Download the database of the repo with `config` into the store, from the
/// first of its servers that has it, and return a record of it to save
/// once it has been checked.
pub fn fetch_db(workers: &Workers, store: &Store, config: &Config) -> Result<SyncRecord> {
    let result = Mutex::new(None);
    download::download_all(
        workers,
        vec![db_request(config, None)?],
        &AtomicBool::new(false),
        |_, data, downloaded| {
            *result.lock().unwrap() = Some(db_record(store, &data, downloaded)?);
            Ok(())
        },
    )?;
    let record = result.into_inner().unwrap();
    record.context("downloading the database didn't finish")
}

/// Load the database that `record` refers to from the store, and read it
/// in a worker.
pub fn load_db(workers: &Workers, store: &Store, record: &SyncRecord) -> Result<Vec<DbEntry>> {
    let db = File::from(store.open_blob(&record.hash)?);
    read_db(workers, db).with_context(|| format!("reading database from {}", record.url))
}

/// Read a database in a worker that can access only `db`, and validate
/// the entries.
fn read_db(workers: &Workers, db: File) -> Result<Vec<DbEntry>> {
    use rustix::pipe::{PipeFlags, pipe_with};
    let (result_r, result_w) = pipe_with(PipeFlags::CLOEXEC).context("creating pipe")?;
    let w = workers.spawn(&read_db_worker::KIND, db.into(), result_w, &[], &[])?;
    let result = worker::read_result(&mut BufReader::new(File::from(result_r))).and_then(|json| {
        let entries: Vec<DbEntry> =
            serde_json::from_slice(&json).context("parsing result from worker")?;
        validate(&entries)?;
        Ok(entries)
    });
    w.finish(result)
}

/// A package in a repo's database. Sent by the worker that reads the
/// database, so to be [validated](validate) before use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbEntry {
    /// The entry's directory in the database, `NAME-VERSION`.
    pub dir: String,
    /// File name of the package on the server.
    pub filename: String,
    pub name: String,
    pub base: Option<String>,
    pub version: String,
    /// Size of the package file.
    pub csize: u64,
    /// Size of the installed package.
    pub isize: Option<u64>,
    /// SHA-256 of the package file, 64 hex digits.
    pub sha256: String,
    /// The package's detached signature.
    #[serde(with = "hex_option")]
    pub pgpsig: Option<Vec<u8>>,
    pub arch: String,
    /// Dependencies, provides, conflicts and replaces as in the
    /// database (`name`, or `name` with a version constraint).
    pub depends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
}

mod hex_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&crate::manifest::hex_encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| crate::manifest::hex_decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Check the entries a worker read from a database: names, versions and
/// file names are well-formed, each entry's directory matches its name
/// and version, names are unique, hashes are SHA-256 and signatures not
/// too large.
pub fn validate(entries: &[DbEntry]) -> Result<()> {
    let mut names = HashSet::new();
    for e in entries {
        let what = || format!("database entry {:?}", e.dir);
        check_name(&e.name).with_context(what)?;
        if let Some(base) = &e.base {
            check_name(base).with_context(what)?;
        }
        check_version(&e.version).with_context(what)?;
        ensure!(
            e.dir == format!("{}-{}", e.name, e.version),
            "{}: directory doesn't match name {} and version {}",
            what(),
            e.name,
            e.version
        );
        ensure!(names.insert(&e.name), "duplicate package {}", e.name);
        check_file_name(&e.filename).with_context(what)?;
        ensure!(
            e.sha256.len() == 64 && e.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: bad SHA-256 {:?}",
            what(),
            e.sha256
        );
        if let Some(sig) = &e.pgpsig {
            ensure!(
                sig.len() as u64 <= MAX_SIGNATURE_SIZE,
                "{}: signature larger than {MAX_SIGNATURE_SIZE} bytes",
                what()
            );
        }
        ensure!(
            !e.arch.is_empty()
                && e.arch.len() <= MAX_FIELD
                && e.arch
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "{}: bad architecture {:?}",
            what(),
            e.arch
        );
        for dep in [&e.depends, &e.provides, &e.conflicts, &e.replaces]
            .into_iter()
            .flatten()
        {
            ensure!(
                !dep.is_empty()
                    && dep.len() <= MAX_FIELD
                    && dep.bytes().all(|b| b.is_ascii_graphic()),
                "{}: bad dependency {dep:?}",
                what()
            );
        }
    }
    Ok(())
}

/// A package name: ASCII letters, digits and `@._+-`, not starting with
/// `-` or `.`.
pub fn check_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_FIELD
            && !name.starts_with(['-', '.'])
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b)),
        "bad package name {name:?}"
    );
    Ok(())
}

/// A full version, `[EPOCH:]PKGVER-PKGREL`: ASCII letters, digits and
/// `._+~` in each part, the epoch digits only.
pub fn check_version(version: &str) -> Result<()> {
    let bad = || format!("bad version {version:?}");
    ensure!(version.len() <= MAX_FIELD, bad());
    let (epoch, rest) = version.split_once(':').unwrap_or(("0", version));
    let (pkgver, pkgrel) = rest.rsplit_once('-').with_context(bad)?;
    let part = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+~".contains(&b))
    };
    ensure!(
        !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()),
        bad()
    );
    ensure!(part(pkgver) && part(pkgrel), bad());
    Ok(())
}

/// A package file name: no path, of ASCII letters, digits and `@._+~:-`,
/// not starting with `.`.
fn check_file_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_FIELD
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+~:-".contains(&b)),
        "bad file name {name:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_ids() {
        assert_eq!(repo_id("core").unwrap(), "@arch/core");
        assert_eq!(repo_id("@arch/core").unwrap(), "@arch/core");
        assert_eq!(repo_id(repo::LOCAL).unwrap(), LOCAL_REPO);
        assert_eq!(repo_id(LOCAL_REPO).unwrap(), LOCAL_REPO);
        for bad in ["@deb/main", "@arch/@arch/core", "a/b", ""] {
            assert!(repo_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dependencies() {
        let dep = |s| parse_dep(s).unwrap().to_string();
        for s in [
            "glibc",
            "glibc>=2.40",
            "a<1",
            "a<=1:2-3",
            "a>1",
            "libfoo.so=1-64",
        ] {
            assert_eq!(dep(s), s);
        }
        assert_eq!(
            parse_dep("a>=1").unwrap(),
            Dep {
                name: "a".into(),
                version: Some((Op::Ge, "1".into()))
            }
        );
        for bad in ["", ">=1", "a>=", "a=>1", "a==1", "a b", "a>=1 2"] {
            assert!(parse_dep(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_provide("libfoo.so=1-64").unwrap(),
            Provide {
                name: "libfoo.so".into(),
                version: Some("1-64".into())
            }
        );
        assert_eq!(parse_provide("sh").unwrap().version, None);
        assert!(parse_provide("sh>=1").is_err());
    }

    #[test]
    fn imported_packages() {
        let pkg = |name: &str, version: &str, depend: &str| {
            let section = ArchSection {
                depends: vec![depend.into()],
                provides: vec!["sh".into(), "libfoo.so=1-64".into()],
                conflicts: vec!["old<2".into()],
                install: None,
                hooks: vec![],
            };
            Package::<()> {
                name: name.into(),
                version: version.into(),
                entries: vec![],
                sections: [section.into_section(vec![]).unwrap()].into(),
                overlay: None,
            }
        };
        let c = package_candidate(&pkg("bash", "5.3-1", "glibc>=2.40")).unwrap();
        assert_eq!((&*c.name, &*c.version), ("bash", "5.3-1"));
        assert_eq!(c.depends[0].to_string(), "glibc>=2.40");
        assert_eq!(c.provides[1].version.as_deref(), Some("1-64"));
        assert_eq!(c.conflicts[0].to_string(), "old<2");
        assert!(package_candidate(&pkg("ba sh", "5.3-1", "glibc")).is_err());
        assert!(package_candidate(&pkg("bash", "5.3", "glibc")).is_err());
        assert!(package_candidate(&pkg("bash", "5.3-1", "gl\u{1b}ibc")).is_err());
    }

    #[test]
    fn urls() {
        let servers = |s: &[&str]| s.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let strings = |urls: Vec<Url>| urls.iter().map(Url::to_string).collect::<Vec<_>>();
        let c = Config::new(
            &servers(&["https://mirror.example/$repo/os/$arch/"]),
            "core",
        )
        .unwrap();
        assert_eq!(
            strings(c.db_urls().unwrap()),
            ["https://mirror.example/core/os/x86_64/core.db"]
        );
        let c = Config::new(
            &servers(&["http://example.org/fixed", "https://b.example/$repo"]),
            "custom",
        )
        .unwrap();
        assert_eq!(
            strings(c.db_urls().unwrap()),
            [
                "http://example.org/fixed/custom.db",
                "https://b.example/custom/custom.db"
            ]
        );
        assert_eq!(
            strings(c.package_urls("a-1-1-any.pkg.tar.zst").unwrap()),
            [
                "http://example.org/fixed/a-1-1-any.pkg.tar.zst",
                "https://b.example/custom/a-1-1-any.pkg.tar.zst"
            ]
        );
        assert!(Config::new(&servers(&["ftp://x/$repo"]), "core").is_err());
        assert!(Config::new(&servers(&["https://x/$repo"]), "a/b").is_err());
        assert!(Config::new(&[], "core").is_err());
        // The same server twice, also when written differently.
        let twice = servers(&["https://x/$repo", "https://x/core/"]);
        assert!(Config::new(&twice, "core").is_err());
    }

    #[test]
    fn mirrorlists() {
        let text = "\
            ## Worldwide\n\
            Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n\
            #Server = https://commented.example/$repo/os/$arch\n\
            \n\
            Server=http://b.example/$repo/os/$arch  \n";
        assert_eq!(
            parse_mirrorlist(text).unwrap(),
            [
                "https://geo.mirror.pkgbuild.com/$repo/os/$arch",
                "http://b.example/$repo/os/$arch"
            ]
        );
        assert!(parse_mirrorlist("").unwrap().is_empty());
        for bad in ["[core]", "Include = /etc/x", "Server =", "Server https://x"] {
            let e = parse_mirrorlist(bad).unwrap_err().to_string();
            assert!(e.contains("line 1"), "{e}");
        }
    }
}
