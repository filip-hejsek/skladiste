//! Repositories: named sources of packages, and the unit of trust. A build
//! lists the repos it may use; restrictions apply per repo only.
//!
//! A repo's configuration and its synced databases are kept in the store
//! (see [`crate::store`]). What a repo's configuration and database contain
//! depends on the frontend (e.g. [`crate::arch::repo`]); the core keeps
//! only a [`SyncRecord`] of each database it fetched.
//!
//! Each package format has its own namespace: the store knows a repo by
//! its id `@FORMAT/NAME` (see [`id`]), e.g. `@arch/core`, so that formats
//! don't compete for names.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::manifest::Hash;
use crate::object::{Index, Object, Ref, Refs};
use serde_json::Value;

/// Name of the pseudo-repo of a format's packages imported from files or
/// URLs (id `@FORMAT/@local`).
pub const LOCAL: &str = "@local";

/// Longest repo name accepted.
const MAX_NAME: usize = 64;

/// Longest format name accepted.
const MAX_FORMAT: usize = 16;

/// The id of repo `name` (a repo name or [`LOCAL`]) of package format
/// `format`: `@FORMAT/NAME`.
pub fn id(format: &str, name: &str) -> Result<String> {
    let id = format!("@{format}/{name}");
    check_id(&id)?;
    Ok(id)
}

/// Check a repo id (see [`id`]).
pub fn check_id(id: &str) -> Result<()> {
    split_id(id).map(drop)
}

/// The format and the name of the repo with id `id`.
pub fn split_id(id: &str) -> Result<(&str, &str)> {
    let Some((format, name)) = id.strip_prefix('@').and_then(|s| s.split_once('/')) else {
        bail!("bad repo id {id:?} (not @FORMAT/NAME)");
    };
    check_format(format)?;
    if name != LOCAL {
        check_name(name)?;
    }
    Ok((format, name))
}

/// Check the name of a package format: ASCII lowercase letters and
/// digits, starting with a letter.
pub fn check_format(format: &str) -> Result<()> {
    ensure!(
        format.len() <= MAX_FORMAT
            && format.starts_with(|c: char| c.is_ascii_lowercase())
            && format
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "bad package format {format:?}"
    );
    Ok(())
}

/// Check the name of a configured repo: ASCII letters, digits and `._+-`,
/// not starting with `.` or `-`. Names starting with `@` are reserved for
/// pseudo-repos such as [`LOCAL`].
pub fn check_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_NAME
            && !name.starts_with(['.', '-'])
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
        "bad repo name {name:?} (allowed: ASCII letters, digits and ._+-, not first . or -)"
    );
    Ok(())
}

/// One fetched version of a repo's database (a snapshot): an object
/// ([`SyncRecord::to_object`]) that refers to the database, a blob, and
/// whose id `repos/<repo>/syncs/<fetched>` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecord {
    /// The database's store blob.
    pub hash: Hash,
    pub size: u64,
    /// Where it was downloaded from.
    pub url: String,
    /// When the download finished, by the supervisor's clock, as
    /// [`timestamp`] formats it.
    pub fetched: String,
    /// The server's `Last-Modified` and `ETag` headers: untrusted, for
    /// information only.
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    /// A value that only this version of the database has, if the server
    /// gave one ([`crate::download::Downloaded::validator`]): the next
    /// sync asks the same URL for the database only if it changed.
    pub validator: Option<String>,
}

/// A sync record as an object's body stores it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSync {
    database: Index,
    size: u64,
    url: String,
    fetched: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validator: Option<String>,
}

impl SyncRecord {
    /// The record as an object: its references and body.
    pub fn to_object(&self) -> Result<(Refs, Value)> {
        let mut refs = Refs::new();
        let body = serde_json::to_value(StoredSync {
            database: refs.add(Ref::Blob(self.hash)),
            size: self.size,
            url: self.url.clone(),
            fetched: self.fetched.clone(),
            last_modified: self.last_modified.clone(),
            etag: self.etag.clone(),
            validator: self.validator.clone(),
        })?;
        Ok((refs, body))
    }

    /// The record in `obj`.
    pub fn from_object(obj: &Object) -> Result<SyncRecord> {
        let s: StoredSync = serde_json::from_value(obj.body.clone())?;
        Ok(SyncRecord {
            hash: obj.blob(s.database)?,
            size: s.size,
            url: s.url,
            fetched: s.fetched,
            last_modified: s.last_modified,
            etag: s.etag,
            validator: s.validator,
        })
    }
}

/// `time` in UTC as `YYYY-MM-DDTHH:MM:SS.uuuuuuZ`. Of fixed width (for
/// years 1970 to 9999), so these sort by time as strings.
pub fn timestamp(time: SystemTime) -> String {
    let d = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86400, secs % 86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        d.subsec_micros()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn names() {
        for good in ["core", "extra-testing", "my_repo.1", "a+b", "A"] {
            check_name(good).unwrap();
        }
        for bad in ["", ".x", "-x", "a/b", "@local", "é", &"a".repeat(65)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ids() {
        assert_eq!(id("arch", "core").unwrap(), "@arch/core");
        assert_eq!(id("arch", LOCAL).unwrap(), "@arch/@local");
        assert_eq!(split_id("@deb2/main").unwrap(), ("deb2", "main"));
        for bad in [
            "core",
            "@arch",
            "@arch/",
            "@/core",
            "@Arch/core",
            "@2/core",
            "@arch/@other",
            "@arch/a/b",
            "@arch/..",
            "@../core",
        ] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000000Z");
        let t = UNIX_EPOCH + Duration::new(1_795_336_898, 123_456_789);
        assert_eq!(timestamp(t), "2026-11-22T08:41:38.123456Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(timestamp(leap), "2000-02-29T00:00:00.000000Z");
    }
}
