//! Arch repos: their configuration and databases (pacman's sync dbs).
//!
//! A repo's database (`core.db`) is a gzip-compressed tar archive with a
//! directory `NAME-VERSION/` per package, holding a `desc` file. Arch
//! doesn't sign its databases, so they are only as trustworthy as the
//! mirror that serves them; packages are signed.
//!
//! A database is untrusted input, so [`read_db`] reads only the stream it
//! is given; `skl` runs it in a sandboxed worker and checks the result
//! with [`validate`].

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::arch::signature::MAX_SIGNATURE_SIZE;
use crate::http::Url;
use crate::manifest::Package;
use crate::repo::{self, SyncRecord};
use crate::resolve::{Candidate, Dep, Op, Provide};
use crate::store::Store;
use crate::worker::{Downloaded, Request, Workers};

/// Largest `desc` file accepted (most are under 2 KiB).
const MAX_DESC: u64 = 1 << 20;
/// Longest name, version, file name or dependency accepted.
const MAX_FIELD: usize = 256;

/// The architecture images are built for, as in pacman's `$arch`.
pub const ARCH: &str = "x86_64";

/// Largest database accepted (`extra.db` is about 8 MiB).
pub const MAX_DB_SIZE: u64 = 64 << 20;

/// Configuration of an Arch repo, kept in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Where the repo's files are, in the format of pacman's `Server`:
    /// `$repo` stands for [`Config::db`] and `$arch` for [`ARCH`].
    pub server: String,
    /// Name of the database on the server: `core` for `core.db`.
    pub db: String,
}

impl Config {
    /// Check that `db` is a plain name and `server` gives valid URLs.
    pub fn new(server: &str, db: &str) -> Result<Config> {
        repo::check_name(db).context("bad database name")?;
        let config = Config {
            server: server.to_owned(),
            db: db.to_owned(),
        };
        config.db_url()?;
        Ok(config)
    }

    /// `server` with `$repo` and `$arch` replaced.
    fn base(&self) -> String {
        let base = self
            .server
            .replace("$repo", &self.db)
            .replace("$arch", ARCH);
        base.trim_end_matches('/').to_owned()
    }

    /// URL of the database, `<server>/<db>.db`.
    pub fn db_url(&self) -> Result<Url> {
        Url::parse(&format!("{}/{}.db", self.base(), self.db))
    }

    /// URL of a package file, `<server>/<file name>`.
    pub fn package_url(&self, file_name: &str) -> Result<Url> {
        Url::parse(&format!("{}/{file_name}", self.base()))
    }
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
        let record = store
            .latest_sync(repo)?
            .with_context(|| format!("repo {repo} was never synced (run `skl sync {repo}`)"))?;
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
    candidate(
        &pkg.name,
        &pkg.version,
        &pkg.depends,
        &pkg.provides,
        &pkg.conflicts,
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
/// memory. Databases aren't signed, so if one changes on the server while
/// it is downloaded, the new one is as good.
pub fn db_request(config: &Config) -> Result<Request<Vec<u8>>> {
    Ok(Request {
        url: config.db_url()?,
        max_size: MAX_DB_SIZE,
        restart_if_changed: true,
        sink: Vec::new(),
    })
}

/// Add the database `data`, downloaded from `url` just now, to the store,
/// and return a record of it to save once it has been checked.
pub fn db_record(
    store: &Store,
    url: &Url,
    mut data: &[u8],
    downloaded: Downloaded,
) -> Result<SyncRecord> {
    let fetched = repo::timestamp(SystemTime::now());
    let added = store.add_object(&mut data)?;
    Ok(SyncRecord {
        hash: added.hash,
        size: added.size,
        url: url.to_string(),
        fetched,
        last_modified: downloaded.last_modified,
        etag: downloaded.etag,
    })
}

/// Download the database of the repo with `config` into the store, and
/// return a record of it to save once it has been checked.
pub fn fetch_db(workers: &Workers, store: &Store, config: &Config) -> Result<SyncRecord> {
    let request = db_request(config)?;
    let (data, downloaded) = workers.download(&request.url, request.sink, request.max_size)?;
    db_record(store, &request.url, &data, downloaded)
}

/// Load the database that `record` refers to from the store, and read it
/// in a worker.
pub fn load_db(workers: &Workers, store: &Store, record: &SyncRecord) -> Result<Vec<DbEntry>> {
    let db = File::from(store.open_object(&record.hash)?);
    workers
        .read_arch_db(db)
        .with_context(|| format!("reading database from {}", record.url))
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

/// Read a repo's database (gzip- or zstd-compressed tar).
pub fn read_db(db: impl Read) -> Result<Vec<DbEntry>> {
    let mut reader = BufReader::new(db);
    let magic = reader.fill_buf()?;
    let decoder: Box<dyn Read> = if magic.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::bufread::GzDecoder::new(reader))
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(zstd::Decoder::with_buffer(reader)?)
    } else {
        bail!("unsupported compression (only gzip and zstd are supported)");
    };
    let mut entries = Vec::new();
    for entry in tar::Archive::new(decoder).entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path = path
            .to_str()
            .with_context(|| format!("non-UTF-8 path: {}", path.display()))?
            .trim_end_matches('/')
            .to_owned();
        match entry.header().entry_type() {
            tar::EntryType::Directory => continue,
            tar::EntryType::Regular | tar::EntryType::Continuous => {}
            other => bail!("{path}: unexpected entry type {other:?}"),
        }
        let Some((dir, "desc")) = path.split_once('/') else {
            bail!("{path}: unexpected file (only NAME-VERSION/desc is supported)");
        };
        ensure!(
            entry.size() <= MAX_DESC,
            "{path}: larger than {MAX_DESC} bytes"
        );
        let mut desc = String::new();
        entry
            .read_to_string(&mut desc)
            .with_context(|| format!("reading {path}"))?;
        entries.push(parse_desc(dir, &desc).with_context(|| format!("in {path}"))?);
    }
    Ok(entries)
}

/// Parse a `desc` file: sections of a `%NAME%` line followed by one value
/// per line, ending with an empty line.
fn parse_desc(dir: &str, desc: &str) -> Result<DbEntry> {
    let mut fields: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        if line.is_empty() {
            continue;
        }
        let key = line
            .strip_prefix('%')
            .and_then(|l| l.strip_suffix('%'))
            .with_context(|| format!("expected a %KEY% line, found {line:?}"))?;
        ensure!(
            fields.iter().all(|(k, _)| *k != key),
            "duplicate field {key}"
        );
        let values = lines.by_ref().take_while(|l| !l.is_empty()).collect();
        fields.push((key, values));
    }
    let list = |key: &str| -> Vec<String> {
        fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    };
    let optional = |key: &str| -> Result<Option<String>> {
        match fields.iter().find(|(k, _)| *k == key) {
            None => Ok(None),
            Some((_, v)) if v.len() == 1 => Ok(Some(v[0].to_owned())),
            Some(_) => bail!("%{key}% must have one value"),
        }
    };
    let required = |key: &str| optional(key)?.with_context(|| format!("missing %{key}%"));
    let number = |key: &str, s: String| {
        s.parse::<u64>()
            .with_context(|| format!("bad %{key}% {s:?}"))
    };
    let pgpsig = optional("PGPSIG")?
        .map(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .context("bad %PGPSIG%")
        })
        .transpose()?;
    Ok(DbEntry {
        dir: dir.to_owned(),
        filename: required("FILENAME")?,
        name: required("NAME")?,
        base: optional("BASE")?,
        version: required("VERSION")?,
        csize: number("CSIZE", required("CSIZE")?)?,
        isize: optional("ISIZE")?.map(|s| number("ISIZE", s)).transpose()?,
        sha256: required("SHA256SUM")?,
        pgpsig,
        arch: required("ARCH")?,
        depends: list("DEPENDS"),
        provides: list("PROVIDES"),
        conflicts: list("CONFLICTS"),
        replaces: list("REPLACES"),
    })
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

    const GLIBC: &str = "%FILENAME%\nglibc-2.44-1-x86_64.pkg.tar.zst\n\n%NAME%\nglibc\n\n\
        %BASE%\nglibc\n\n%VERSION%\n2.44-1\n\n%DESC%\nGNU C Library\n\n\
        %CSIZE%\n10882312\n\n%ISIZE%\n53124699\n\n%SHA256SUM%\n\
        b6db2293b5c5dde6e0fe2c7e1f916b01a2dd3775f089640d8f8aa7c891057ae0\n\n\
        %PGPSIG%\nAAEC/w==\n\n%ARCH%\nx86_64\n\n\
        %DEPENDS%\nlinux-api-headers>=4.10\ntzdata\nfilesystem\n\n\
        %OPTDEPENDS%\ngd: for memusagestat\n\n";

    /// A gzip-compressed database with the given `desc` files.
    fn make_db(entries: &[(&str, &str)]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        for (dir, desc) in entries {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            h.set_size(0);
            b.append_data(&mut h, format!("{dir}/"), &[][..]).unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_mode(0o644);
            h.set_size(desc.len() as u64);
            b.append_data(&mut h, format!("{dir}/desc"), desc.as_bytes())
                .unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn reads_database() {
        let db = make_db(&[("glibc-2.44-1", GLIBC)]);
        let entries = read_db(&db[..]).unwrap();
        assert_eq!(
            entries,
            [DbEntry {
                dir: "glibc-2.44-1".into(),
                filename: "glibc-2.44-1-x86_64.pkg.tar.zst".into(),
                name: "glibc".into(),
                base: Some("glibc".into()),
                version: "2.44-1".into(),
                csize: 10882312,
                isize: Some(53124699),
                sha256: "b6db2293b5c5dde6e0fe2c7e1f916b01a2dd3775f089640d8f8aa7c891057ae0".into(),
                pgpsig: Some(vec![0, 1, 2, 0xff]),
                arch: "x86_64".into(),
                depends: vec![
                    "linux-api-headers>=4.10".into(),
                    "tzdata".into(),
                    "filesystem".into()
                ],
                provides: vec![],
                conflicts: vec![],
                replaces: vec![],
            }]
        );
        validate(&entries).unwrap();
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains(r#""pgpsig":"000102ff""#), "{json}");
        let back: Vec<DbEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entries);
    }

    #[test]
    fn bad_databases() {
        let err = |db: &[u8]| format!("{:#}", read_db(db).unwrap_err());
        assert!(err(b"plain text").contains("unsupported compression"));
        let missing = GLIBC.replace("%CSIZE%\n10882312\n\n", "");
        assert!(err(&make_db(&[("glibc-2.44-1", &missing)])).contains("missing %CSIZE%"));
        let two = GLIBC.replace("%NAME%\nglibc\n", "%NAME%\nglibc\nother\n");
        assert!(err(&make_db(&[("glibc-2.44-1", &two)])).contains("one value"));
        let dup = format!("{GLIBC}%NAME%\nx\n");
        assert!(err(&make_db(&[("glibc-2.44-1", &dup)])).contains("duplicate field"));
        assert!(err(&make_db(&[("glibc-2.44-1", "junk\n")])).contains("%KEY%"));
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
        let pkg = |name: &str, version: &str, depend: &str| Package::<()> {
            name: name.into(),
            version: version.into(),
            depends: vec![depend.into()],
            provides: vec!["sh".into(), "libfoo.so=1-64".into()],
            conflicts: vec!["old<2".into()],
            entries: vec![],
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
    fn validation() {
        let good = read_db(&make_db(&[("glibc-2.44-1", GLIBC)])[..]).unwrap();
        let check = |f: &dyn Fn(&mut DbEntry)| {
            let mut entries = good.clone();
            f(&mut entries[0]);
            validate(&entries).map_err(|e| format!("{e:#}"))
        };
        assert!(
            check(&|e| e.dir = "glibc-2.45-1".into())
                .unwrap_err()
                .contains("doesn't match")
        );
        assert!(check(&|e| e.filename = "../x".into()).is_err());
        assert!(check(&|e| e.filename = "a/b".into()).is_err());
        assert!(check(&|e| e.sha256.truncate(63)).is_err());
        assert!(check(&|e| e.sha256.replace_range(..1, "g")).is_err());
        assert!(check(&|e| e.pgpsig = Some(vec![0; 65 << 10])).is_err());
        assert!(check(&|e| e.depends.push("a b".into())).is_err());
        assert!(check(&|e| e.arch = "x/y".into()).is_err());
        let mut twice = good.clone();
        twice.extend(good.clone());
        assert!(format!("{:#}", validate(&twice).unwrap_err()).contains("duplicate package"));

        for v in ["1-1", "1:2.3+r4~rc1-1.1", "20261019-1"] {
            check_version(v).unwrap();
        }
        for v in ["1", "-1", "1-", "a:1-1", ":1-1", "1 2-1", "1/2-1"] {
            assert!(check_version(v).is_err(), "{v}");
        }
        for n in ["glibc", "lib32-gcc-libs", "gtk+", "python3.12", "x@y"] {
            check_name(n).unwrap();
        }
        for n in ["", "-x", ".x", "a/b", "a b", "a:b"] {
            assert!(check_name(n).is_err(), "{n}");
        }
    }

    #[test]
    fn urls() {
        let c = Config::new("https://mirror.example/$repo/os/$arch/", "core").unwrap();
        assert_eq!(
            c.db_url().unwrap().to_string(),
            "https://mirror.example/core/os/x86_64/core.db"
        );
        let c = Config::new("http://example.org/fixed", "custom").unwrap();
        assert_eq!(
            c.db_url().unwrap().to_string(),
            "http://example.org/fixed/custom.db"
        );
        assert_eq!(
            c.package_url("a-1-1-any.pkg.tar.zst").unwrap().to_string(),
            "http://example.org/fixed/a-1-1-any.pkg.tar.zst"
        );
        assert!(Config::new("ftp://x/$repo", "core").is_err());
        assert!(Config::new("https://x/$repo", "a/b").is_err());
    }
}
