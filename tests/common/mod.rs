//! Helpers shared by integration tests.

pub(crate) mod minimal_image;

use std::fs::File;
use std::path::Path;

/// Create a new subvolume at `path`, in an existing directory.
pub(crate) fn create_subvolume(path: &Path) {
    let parent = File::open(path.parent().unwrap()).unwrap();
    skladiste::btrfs::create_subvolume_at(&parent, path.file_name().unwrap()).unwrap();
}
