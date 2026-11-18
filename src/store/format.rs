//! Versions of the store format, and migrations between them.
//!
//! A stable version is a number, starting at 1; each one after the first
//! has a migration from the one before. A development version is a
//! random string (`src/store/dev-version`, made by
//! `scripts/new-store-dev-version.sh`), used while the format changes
//! between stable versions: development versions have no order, so a
//! store of one is never migrated. A development build can migrate a
//! store of the latest stable version to its development version, but
//! only when asked to: afterwards only builds with that development
//! version can open the store. When a development version becomes
//! stable, it gets the next number, and its migration joins the others.

use std::fmt;
use std::os::fd::BorrowedFd;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A version of the store format, as the store manifest records it: a
/// number for a stable version, a string for a development version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FormatVersion {
    Stable(u64),
    Dev(String),
}

impl fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatVersion::Stable(n) => write!(f, "{n}"),
            FormatVersion::Dev(s) => write!(f, "{s:?}"),
        }
    }
}

/// Changes a store, given its directory, from one version of the format
/// to the next. The manifest is updated afterwards, so a migration that
/// was interrupted is run again: it must work on a store it has already
/// partly or fully changed.
pub(super) type Migration = fn(BorrowedFd<'_>) -> Result<()>;

/// The store formats a build of skl knows.
pub(super) struct Formats {
    /// The latest stable version, or 0 if there is none yet.
    pub(super) latest_stable: u64,
    /// `migrations[i]` migrates version `i + 1` to `i + 2`.
    pub(super) migrations: &'static [Migration],
    /// The development version this build uses instead of
    /// `latest_stable`, if any.
    pub(super) dev: Option<DevFormat>,
}

pub(super) struct DevFormat {
    pub(super) version: &'static str,
    /// Migrates `latest_stable` to this version.
    pub(super) migration: Option<Migration>,
}

/// The formats of this build.
pub(super) const FORMATS: Formats = Formats {
    latest_stable: 0,
    migrations: &[],
    dev: Some(DevFormat {
        version: include_str!("dev-version").trim_ascii(),
        migration: None,
    }),
};

const _: () = FORMATS.check();

impl Formats {
    /// Panics (at compile time for a constant) unless every stable version
    /// but the first has a migration and there is a version to use.
    pub(super) const fn check(&self) {
        if self.latest_stable == 0 {
            assert!(
                self.migrations.is_empty(),
                "migrations without a stable version"
            );
            match &self.dev {
                None => panic!("no stable version and no development version"),
                Some(dev) => assert!(
                    dev.migration.is_none(),
                    "a development migration without a stable version"
                ),
            }
        } else {
            assert!(
                self.migrations.len() as u64 == self.latest_stable - 1,
                "every stable version but the first needs a migration"
            );
        }
    }

    /// The version this build uses.
    pub(super) fn current(&self) -> FormatVersion {
        match &self.dev {
            Some(dev) => FormatVersion::Dev(dev.version.to_owned()),
            None => FormatVersion::Stable(self.latest_stable),
        }
    }

    /// Fails with [`WrongVersion`] unless `found` is the current version.
    pub(super) fn ensure_current(&self, found: &FormatVersion) -> Result<(), WrongVersion> {
        match self.plan(found, false) {
            Ok(steps) if steps.is_empty() => Ok(()),
            Ok(_) => Err(WrongVersion {
                found: found.clone(),
                current: self.current(),
                problem: VersionProblem::NeedsMigration { to_dev: false },
            }),
            Err(e) => Err(e),
        }
    }

    /// The migrations that bring a store of version `found` to the current
    /// version, in order; none if it is the current version. Fails with
    /// [`WrongVersion`] if there are none or `found` is the latest stable
    /// version and the migration is to a development version, unless
    /// `allow_dev`.
    pub(super) fn plan(
        &self,
        found: &FormatVersion,
        allow_dev: bool,
    ) -> Result<Vec<Step>, WrongVersion> {
        let current = self.current();
        if *found == current {
            return Ok(Vec::new());
        }
        let error = |problem| WrongVersion {
            found: found.clone(),
            current: current.clone(),
            problem,
        };
        let n = match *found {
            FormatVersion::Stable(n) if (1..=self.latest_stable).contains(&n) => n,
            FormatVersion::Stable(n) if n > self.latest_stable => {
                return Err(error(VersionProblem::Newer));
            }
            _ => return Err(error(VersionProblem::Unknown)),
        };
        let mut steps: Vec<Step> = (n..self.latest_stable)
            .map(|from| Step {
                migration: self.migrations[from as usize - 1],
                to: FormatVersion::Stable(from + 1),
            })
            .collect();
        if let Some(dev) = &self.dev {
            let Some(migration) = dev.migration else {
                return Err(error(VersionProblem::NoDevMigration));
            };
            if !allow_dev {
                return Err(error(VersionProblem::NeedsMigration { to_dev: true }));
            }
            steps.push(Step {
                migration,
                to: current,
            });
        }
        Ok(steps)
    }
}

/// One migration, and the version it leaves the store at.
pub(super) struct Step {
    pub(super) migration: Migration,
    pub(super) to: FormatVersion,
}

/// A store's format version isn't the one this skl uses: the error of
/// [`Store::open`](super::Store::open) and others (found with
/// [`anyhow::Error::downcast_ref`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongVersion {
    pub found: FormatVersion,
    pub current: FormatVersion,
    pub problem: VersionProblem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionProblem {
    /// [`Store::migrate`](super::Store::migrate) can migrate the store;
    /// if `to_dev`, to a development version, which needs `allow_dev`.
    NeedsMigration { to_dev: bool },
    /// The store is of a newer stable version.
    Newer,
    /// This development build can't migrate from the latest stable
    /// version.
    NoDevMigration,
    /// A development version of another build, or a number that was
    /// never a stable version: no migration is possible.
    Unknown,
}

impl fmt::Display for WrongVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let WrongVersion { found, current, .. } = self;
        write!(f, "the store has format version {found}, ")?;
        match (self.problem, found) {
            (VersionProblem::NeedsMigration { to_dev: false }, _) => {
                write!(
                    f,
                    "older than version {current} of this skl; it needs to be migrated"
                )
            }
            (VersionProblem::NeedsMigration { to_dev: true }, _) => write!(
                f,
                "but this development build of skl uses version {current}; it can migrate \
                 the store, after which only builds of that version can open it"
            ),
            (VersionProblem::Newer, _) => write!(f, "newer than version {current} of this skl"),
            (VersionProblem::NoDevMigration, _) => write!(
                f,
                "but this development build of skl uses version {current} and can't migrate it"
            ),
            (VersionProblem::Unknown, FormatVersion::Dev(_)) => write!(
                f,
                "a development version of another build of skl (this one uses {current}); \
                 it can't be migrated"
            ),
            (VersionProblem::Unknown, FormatVersion::Stable(_)) => write!(
                f,
                "which no skl has as a stable version (this one uses {current}); \
                 it can't be migrated"
            ),
        }
    }
}

impl std::error::Error for WrongVersion {}

#[cfg(test)]
mod tests {
    use super::*;
    use FormatVersion::{Dev, Stable};

    fn m1(_: BorrowedFd<'_>) -> Result<()> {
        Ok(())
    }
    fn m2(_: BorrowedFd<'_>) -> Result<()> {
        Ok(())
    }
    fn mdev(_: BorrowedFd<'_>) -> Result<()> {
        Ok(())
    }

    fn dev(migration: Option<Migration>) -> Option<DevFormat> {
        Some(DevFormat {
            version: "dev-a",
            migration,
        })
    }

    /// The versions the plan leads through, or the problem.
    fn plan(
        formats: &Formats,
        found: FormatVersion,
        allow_dev: bool,
    ) -> Result<Vec<FormatVersion>, VersionProblem> {
        formats.check();
        match formats.plan(&found, allow_dev) {
            Ok(steps) => Ok(steps.into_iter().map(|s| s.to).collect()),
            Err(e) => {
                assert_eq!(e.found, found);
                assert_eq!(e.current, formats.current());
                Err(e.problem)
            }
        }
    }

    #[test]
    fn this_dev_version_is_well_formed() {
        let dev = FORMATS.dev.as_ref().unwrap().version;
        let hex = dev.strip_prefix("dev-").unwrap();
        assert!(
            hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{dev:?}"
        );
    }

    #[test]
    fn manifest_versions() {
        let parse = |s| serde_json::from_str::<FormatVersion>(s).unwrap();
        assert_eq!(parse("3"), Stable(3));
        assert_eq!(parse(r#""dev-a""#), Dev("dev-a".into()));
        assert!(serde_json::from_str::<FormatVersion>("-1").is_err());
        assert_eq!(serde_json::to_string(&Dev("x".into())).unwrap(), r#""x""#);
    }

    #[test]
    fn stable_migrations() {
        let formats = Formats {
            latest_stable: 3,
            migrations: &[m1, m2],
            dev: None,
        };
        assert_eq!(plan(&formats, Stable(3), false), Ok(vec![]));
        assert_eq!(
            plan(&formats, Stable(1), false),
            Ok(vec![Stable(2), Stable(3)])
        );
        assert_eq!(plan(&formats, Stable(2), true), Ok(vec![Stable(3)]));
        assert_eq!(plan(&formats, Stable(4), false), Err(VersionProblem::Newer));
        assert_eq!(
            plan(&formats, Stable(0), false),
            Err(VersionProblem::Unknown)
        );
        assert_eq!(
            plan(&formats, Dev("dev-a".into()), false),
            Err(VersionProblem::Unknown)
        );
    }

    #[test]
    fn dev_migrations() {
        let formats = Formats {
            latest_stable: 2,
            migrations: &[m1],
            dev: dev(Some(mdev)),
        };
        let to_dev = Err(VersionProblem::NeedsMigration { to_dev: true });
        assert_eq!(plan(&formats, Dev("dev-a".into()), false), Ok(vec![]));
        assert_eq!(
            plan(&formats, Dev("dev-b".into()), true),
            Err(VersionProblem::Unknown)
        );
        assert_eq!(plan(&formats, Stable(2), false), to_dev);
        assert_eq!(plan(&formats, Stable(1), false), to_dev);
        assert_eq!(
            plan(&formats, Stable(1), true),
            Ok(vec![Stable(2), Dev("dev-a".into())])
        );
        assert_eq!(plan(&formats, Stable(3), true), Err(VersionProblem::Newer));
        let formats = Formats {
            dev: dev(None),
            ..formats
        };
        assert_eq!(
            plan(&formats, Stable(2), true),
            Err(VersionProblem::NoDevMigration)
        );
        // Before the first stable version, numbers are unknown.
        let formats = Formats {
            latest_stable: 0,
            migrations: &[],
            dev: dev(None),
        };
        assert_eq!(
            plan(&formats, Stable(0), true),
            Err(VersionProblem::Unknown)
        );
        assert_eq!(plan(&formats, Stable(1), true), Err(VersionProblem::Newer));
    }

    #[test]
    #[should_panic(expected = "needs a migration")]
    fn stable_versions_need_migrations() {
        Formats {
            latest_stable: 3,
            migrations: &[m1],
            dev: None,
        }
        .check();
    }
}
