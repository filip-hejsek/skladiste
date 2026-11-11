//! skladiště: a package manager built on a content-addressed store on btrfs.

pub mod arch;
pub mod btrfs;
mod bwrap;
pub mod http;
pub mod install;
pub mod jobs;
pub mod manifest;
mod sandbox;
pub mod store;
pub mod worker;
