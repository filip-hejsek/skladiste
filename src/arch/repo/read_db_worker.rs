//! The worker that reads a repo's database (see [`KIND`]).

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::FromRawFd;

use anyhow::{Context, Result, bail, ensure};

use super::DbEntry;
use crate::sandbox::{self, Policy};
use crate::worker::{Args, Kind, NO_CAPS};

/// Largest `desc` file accepted (most are under 2 KiB).
const MAX_DESC: u64 = 1 << 20;

/// Address space limit of the worker, as for the import worker: zstd's
/// default limit on the decoding window is 128 MiB.
const MAX_MEMORY: u64 = 1 << 30;

/// The worker that reads a database: fd 0 is the database, fd 1 a pipe. It
/// reads it with [`read_db`] and sends the entries in `DONE`; the
/// supervisor validates them ([`super::validate`]). No filesystem access,
/// no ioctls.
pub(crate) const KIND: Kind = Kind {
    name: "read-arch-db",
    dirs: &[],
    caps: NO_CAPS,
    main,
};

fn main(args: Args) -> Result<Vec<u8>> {
    args.no_extra()?;
    // SAFETY: the supervisor passes the database as fd 0.
    let db = unsafe { File::from_raw_fd(0) };
    let policy = Policy {
        max_memory: Some(MAX_MEMORY),
        ..Policy::default()
    };
    sandbox::confine(args.layers, &policy)?;
    Ok(serde_json::to_vec(&read_db(db)?)?)
}

/// Read a repo's database (gzip- or zstd-compressed tar).
fn read_db(db: impl Read) -> Result<Vec<DbEntry>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::repo::{check_name, check_version, validate};

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
}
