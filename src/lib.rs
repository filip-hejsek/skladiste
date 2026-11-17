//! skladiště: a package manager built on a content-addressed store on btrfs.

pub mod arch;
pub mod btrfs;
mod bwrap;
pub mod diff;
pub mod download;
pub mod http;
pub mod install;
pub mod jobs;
pub mod manifest;
pub mod repo;
pub mod resolve;
pub mod run;
mod sandbox;
pub mod store;
pub mod worker;
