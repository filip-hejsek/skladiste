//! End-to-end test: synthetic Arch packages → store → image subvolume.
//! Skipped when the cargo target directory is not on btrfs.

use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use skladiste::{arch, install, manifest::Package, store::Store};
use tar::{EntryType, Header};

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

enum Item<'a> {
    Dir(&'a str, u32),
    File(&'a str, u32, &'a [u8]),
    FileXattr(&'a str, &'a [u8], &'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    Hardlink(&'a str, &'a str),
}

fn make_package(dir: &Path, name: &str, items: &[Item]) -> PathBuf {
    let path = dir.join(format!("{name}-1-1-any.pkg.tar.zst"));
    let enc = zstd::Encoder::new(File::create(&path).unwrap(), 3).unwrap();
    let mut b = tar::Builder::new(enc);

    let pkginfo = format!("pkgname = {name}\npkgver = 1-1\n");
    let mut h = Header::new_gnu();
    h.set_size(pkginfo.len() as u64);
    h.set_mode(0o644);
    b.append_data(&mut h, ".PKGINFO", pkginfo.as_bytes())
        .unwrap();

    for item in items {
        let mut h = Header::new_ustar();
        h.set_mtime(1_000_000);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mode(0o644);
        match *item {
            Item::Dir(p, mode) => {
                h.set_entry_type(EntryType::Directory);
                h.set_mode(mode);
                h.set_size(0);
                b.append_data(&mut h, p, &[][..]).unwrap();
            }
            Item::File(p, mode, data) => {
                h.set_mode(mode);
                h.set_size(data.len() as u64);
                b.append_data(&mut h, p, data).unwrap();
            }
            Item::FileXattr(p, data, xname, xval) => {
                let key = format!("SCHILY.xattr.{xname}");
                b.append_pax_extensions([(key.as_str(), xval)]).unwrap();
                h.set_mode(0o644);
                h.set_size(data.len() as u64);
                b.append_data(&mut h, p, data).unwrap();
            }
            Item::Symlink(p, target) => {
                h.set_entry_type(EntryType::Symlink);
                h.set_mode(0o777);
                h.set_size(0);
                b.append_link(&mut h, p, target).unwrap();
            }
            Item::Hardlink(p, target) => {
                h.set_entry_type(EntryType::Link);
                h.set_size(0);
                b.append_link(&mut h, p, target).unwrap();
            }
        }
    }
    b.into_inner().unwrap().finish().unwrap();
    path
}

fn import(store: &Store, path: &Path) -> Package {
    arch::import(store, path).unwrap().0
}

#[test]
fn build_image() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::open(&tmp.path().join("store")).unwrap();
    let big = vec![7u8; 1 << 20];

    let base = make_package(
        tmp.path(),
        "base",
        &[
            Item::Dir("usr/", 0o755),
            Item::Dir("usr/bin/", 0o755),
            // Absolute symlink: must resolve inside the image, not on the host.
            Item::Symlink("bin", "/usr/bin"),
            Item::Dir("tmp/", 0o1777),
        ],
    );
    let tools = make_package(
        tmp.path(),
        "tools",
        &[
            Item::Dir("usr/", 0o755),
            Item::Dir("usr/bin/", 0o755),
            // Hard link sorts before its target.
            Item::Hardlink("usr/bin/a-link", "usr/bin/z-tool"),
            Item::File("usr/bin/z-tool", 0o4755, &big),
            Item::File("usr/bin/same", 0o755, &big),
            Item::FileXattr("usr/bin/tagged", b"x", "user.skl.test", b"value"),
            // Installed through the `bin` symlink.
            Item::File("bin/via-symlink", 0o755, b"hi"),
        ],
    );

    let base = import(&store, &base);
    let (tools, stats) = arch::import(&store, &tools).unwrap();
    assert_eq!(stats.files, 4);
    assert_eq!(stats.new_objects, 3, "identical files share one object");

    let img = tmp.path().join("img");
    let report = install::build(&store, &[base, tools], &img).unwrap();
    assert_eq!(report.files, 4);
    assert_eq!(report.hardlinks, 1);
    assert_eq!(report.xattr_failures, 0);

    let tool = fs::metadata(img.join("usr/bin/z-tool")).unwrap();
    assert_eq!(tool.permissions().mode() & 0o7777, 0o4755);
    assert_eq!(tool.mtime(), 1_000_000);
    assert_eq!(tool.nlink(), 2);
    assert_eq!(fs::read(img.join("usr/bin/z-tool")).unwrap(), big);

    let tmp_dir = fs::metadata(img.join("tmp")).unwrap();
    assert_eq!(tmp_dir.permissions().mode() & 0o7777, 0o1777);
    assert_eq!(tmp_dir.mtime(), 1_000_000);

    assert_eq!(fs::read(img.join("usr/bin/via-symlink")).unwrap(), b"hi");
    assert_eq!(
        fs::read_link(img.join("bin")).unwrap(),
        Path::new("/usr/bin")
    );

    let mut value = [0u8; 16];
    let n = rustix::fs::getxattr(img.join("usr/bin/tagged"), "user.skl.test", &mut value).unwrap();
    assert_eq!(&value[..n], b"value");
}

#[test]
fn conflicting_files_are_rejected() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::open(&tmp.path().join("store")).unwrap();
    let a = make_package(tmp.path(), "a", &[Item::File("f", 0o644, b"a")]);
    let b = make_package(tmp.path(), "b", &[Item::File("f", 0o644, b"b")]);
    let pkgs = [import(&store, &a), import(&store, &b)];
    let err = install::build(&store, &pkgs, &tmp.path().join("img")).unwrap_err();
    assert!(err.to_string().contains("conflict: /f"), "{err}");
}
