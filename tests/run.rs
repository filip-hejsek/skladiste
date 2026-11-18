//! Running a program in an image and capturing its changes. Skipped when
//! the cargo target directory is not on btrfs.

mod common;

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::minimal_image;
use skladiste::diff::Change;
use skladiste::manifest::{EntryKind, XattrValue};
use skladiste::store::Store;
use skladiste::worker::Workers;

const BTRFS_SUPER_MAGIC: i64 = 0x9123683e;

fn btrfs_tempdir() -> Option<tempfile::TempDir> {
    let base = env!("CARGO_TARGET_TMPDIR");
    let stat = rustix::fs::statfs(base).unwrap();
    if stat.f_type as i64 != BTRFS_SUPER_MAGIC {
        eprintln!("skipping: {base} is not on btrfs");
        return None;
    }
    Some(tempfile::tempdir_in(base).unwrap())
}

/// What the child changes in the image prepared by the test.
fn make_changes() {
    fs::write("/etc/new", "new").unwrap();
    rustix::fs::setxattr(
        "/etc/new",
        "user.test",
        b"v",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    fs::hard_link("/etc/new", "/etc/new2").unwrap();
    std::os::unix::fs::symlink("new", "/etc/sym").unwrap();
    fs::write("/etc/modified", "after").unwrap();
    fs::set_permissions("/etc/chmodded", PermissionsExt::from_mode(0o600)).unwrap();
    fs::remove_file("/etc/removed").unwrap();
    fs::rename("/etc/renamed", "/etc/renamed2").unwrap();
    fs::remove_dir_all("/olddir").unwrap();
    fs::create_dir("/newdir").unwrap();
    fs::write("/tmp/not-kept", "x").unwrap();
    std::process::exit(3);
}

#[test]
fn captures_changes() {
    if minimal_image::is_child() {
        make_changes();
    }
    let Some(dir) = btrfs_tempdir() else { return };
    let store = Store::init_path(&dir.path().join("store")).unwrap();
    let image = dir.path().join("image");
    common::create_subvolume(&image);
    minimal_image::populate(&image);
    for name in ["modified", "chmodded", "removed", "renamed", "same"] {
        fs::write(image.join("etc").join(name), "before").unwrap();
    }
    fs::create_dir_all(image.join("olddir/sub")).unwrap();
    fs::write(image.join("olddir/sub/f"), "x").unwrap();

    let workers = Workers::new(env!("CARGO_BIN_EXE_skl"));
    let root = File::open(&image).unwrap();
    let args = minimal_image::child_args("captures_changes");
    let child = OsStr::new(minimal_image::CHILD);
    let captured = skladiste::run::run_captured(
        &workers,
        &store,
        root.as_fd(),
        child,
        &args,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(captured.status.code(), Some(3));

    let summary: Vec<String> = captured
        .changes
        .iter()
        .map(|c| {
            let letter = match c {
                Change::Added(_) => 'A',
                Change::Modified(_) => 'M',
                Change::Removed(_) => 'D',
            };
            format!("{letter} {}", c.path())
        })
        .collect();
    assert_eq!(
        summary,
        [
            "M etc",
            "M etc/chmodded",
            "M etc/modified",
            "A etc/new",
            "A etc/new2",
            "A etc/renamed2",
            "A etc/sym",
            "D etc/removed",
            "D etc/renamed",
            "A newdir",
            "D olddir",
        ]
    );
    let entry = |path: &str| {
        captured
            .changes
            .iter()
            .find_map(|c| match c {
                Change::Added(e) | Change::Modified(e) if e.path == path => Some(e),
                _ => None,
            })
            .unwrap()
    };
    let EntryKind::File(content) = entry("etc/new").kind else {
        panic!("not a file");
    };
    let blob = store.open_blob(&content.hash).unwrap();
    assert_eq!(std::io::read_to_string(File::from(blob)).unwrap(), "new");
    assert_eq!(
        entry("etc/new").xattrs.get("user.test"),
        Some(&XattrValue(b"v".to_vec()))
    );
    assert_eq!(
        entry("etc/new2").kind,
        EntryKind::Hardlink {
            target: "etc/new".into()
        }
    );
    assert_eq!(
        entry("etc/sym").kind,
        EntryKind::Symlink {
            target: "new".into()
        }
    );
    assert_eq!(entry("etc/chmodded").mode, 0o600);
    // Contents of the files changed, new to the store: "new", "after" and
    // "before" (chmodded and renamed2).
    assert_eq!(captured.stats.files, 4);
    assert_eq!(captured.stats.new_blobs, 3);
    // The snapshot is gone.
    assert_eq!(
        fs::read_dir(dir.path().join("store/tmp")).unwrap().count(),
        0
    );
    assert!(!Path::new(&image).join("tmp/not-kept").exists());
}

#[test]
fn removes_subvolumes() {
    let Some(dir) = btrfs_tempdir() else { return };
    let sub = dir.path().join("sub");
    common::create_subvolume(&sub);
    fs::create_dir_all(sub.join("a/b")).unwrap();
    fs::write(sub.join("a/b/f"), "x").unwrap();
    fs::set_permissions(sub.join("a"), PermissionsExt::from_mode(0o555)).unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, "kept").unwrap();
    std::os::unix::fs::symlink(&outside, sub.join("link")).unwrap();
    let parent = File::open(dir.path()).unwrap();
    let removal = skladiste::btrfs::remove_subvolume_at(parent.as_fd(), OsStr::new("sub")).unwrap();
    eprintln!("removed: {removal:?}");
    assert!(!sub.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"kept");
}
