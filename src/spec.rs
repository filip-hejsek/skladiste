//! Build specs: what goes into an image before package code runs, as the
//! input of that code.
//!
//! A build spec is an object ([`crate::object`]) with the ids of the
//! packages in the order they are installed and the version of the way
//! skl runs package code ([`BuildSpec::runner`]). The store keeps the
//! synthetic package that running the code made for a spec
//! ([`Store::synthetic`](crate::store::Store::synthetic)), so building the
//! same list again gives the same image without running the code again.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::Hash;
use crate::object::{Index, Object, Ref, Refs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSpec {
    /// Package ids, in the order they are installed.
    pub packages: Vec<Hash>,
    /// The frontend's name for the way it runs package code (e.g.
    /// `arch 1`), changed whenever the environment or the order of the
    /// code changes, so that earlier results aren't reused.
    pub runner: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    packages: Vec<Index>,
    runner: String,
}

impl BuildSpec {
    /// The spec as an object: its references and body.
    pub fn to_object(&self) -> Result<(Refs, Value)> {
        let mut refs = Refs::new();
        let packages = self
            .packages
            .iter()
            .map(|id| refs.add(Ref::Object(*id)))
            .collect();
        let body = serde_json::to_value(Stored {
            packages,
            runner: self.runner.clone(),
        })?;
        Ok((refs, body))
    }

    /// The spec in `obj`.
    pub fn from_object(obj: &Object) -> Result<BuildSpec> {
        let stored: Stored =
            serde_json::from_value(obj.body.clone()).context("parsing the build spec")?;
        let packages = stored
            .packages
            .into_iter()
            .map(|i| obj.object(i))
            .collect::<Result<_>>()?;
        Ok(BuildSpec {
            packages,
            runner: stored.runner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let id = |s: &str| Hash::from(blake3::hash(s.as_bytes()));
        let spec = BuildSpec {
            packages: vec![id("a"), id("b"), id("a")],
            runner: "test 1".into(),
        };
        let (refs, body) = spec.to_object().unwrap();
        let data = crate::object::encode(refs.as_slice(), &body).unwrap();
        let obj = crate::object::decode(&data).unwrap();
        assert_eq!(obj.refs, [Ref::Object(id("a")), Ref::Object(id("b"))]);
        assert_eq!(BuildSpec::from_object(&obj).unwrap(), spec);
    }
}
