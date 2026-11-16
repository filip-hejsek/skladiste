//! Repositories: named sources of packages, and the unit of trust. A build
//! lists the repos it may use; restrictions apply per repo only.
//!
//! A repo's configuration and its synced databases are kept in the store
//! (see [`crate::store`]). What a repo's configuration and database contain
//! depends on the frontend (e.g. [`crate::arch::repo`]); the core keeps
//! only a [`SyncRecord`] of each database it fetched.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::manifest::Hash;

/// Pseudo-repo of packages imported from files or URLs.
pub const LOCAL: &str = "@local";

/// Longest repo name accepted.
const MAX_NAME: usize = 64;

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

/// Check a repo name that may also be a pseudo-repo.
pub(crate) fn check_name_or_local(name: &str) -> Result<()> {
    if name == LOCAL {
        Ok(())
    } else {
        check_name(name)
    }
}

/// One fetched version of a repo's database (a snapshot), kept as
/// `repos/<repo>/syncs/<fetched>.json`. The database itself is a store
/// object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecord {
    /// The database's store object.
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
        check_name_or_local(LOCAL).unwrap();
        assert!(check_name_or_local("@other").is_err());
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
