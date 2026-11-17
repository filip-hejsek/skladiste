//! Helpers shared by the commands of the CLI. Commands of a frontend are
//! in submodules (e.g. [`arch`]).

pub(crate) mod arch;

pub(crate) fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
