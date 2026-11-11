//! skladiště: a package manager built on a content-addressed store on btrfs.

pub mod arch;
pub mod btrfs;
mod bwrap;
pub mod install;
pub mod manifest;
mod sandbox;
pub mod store;
pub mod worker;
