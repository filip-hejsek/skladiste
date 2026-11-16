//! Arch repos: their configuration and databases (pacman's sync dbs).
//!
//! A repo's database (`core.db`) is a gzip-compressed tar archive with a
//! directory per package. Arch doesn't sign its databases, so they are
//! only as trustworthy as the mirror that serves them; packages are
//! signed.

use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::http::Url;
use crate::repo::{self, SyncRecord};
use crate::store::Store;
use crate::worker::Workers;

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
}

/// Download the database of the repo with `config` into the store, and
/// return a record of it to save once it has been checked.
pub fn fetch_db(workers: &Workers, store: &Store, config: &Config) -> Result<SyncRecord> {
    let url = config.db_url()?;
    let mut data = Vec::new();
    let download = workers
        .download(&url, &mut data, MAX_DB_SIZE)
        .with_context(|| format!("downloading {url}"))?;
    let fetched = repo::timestamp(SystemTime::now());
    let added = store.add_object(&mut &data[..])?;
    Ok(SyncRecord {
        hash: added.hash,
        size: added.size,
        url: url.to_string(),
        fetched,
        last_modified: download.last_modified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(Config::new("ftp://x/$repo", "core").is_err());
        assert!(Config::new("https://x/$repo", "a/b").is_err());
    }
}
