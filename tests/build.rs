//! End-to-end test: synthetic Arch packages → store → image subvolume.
//! Skipped when the cargo target directory is not on btrfs.

use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use skladiste::arch::{self, ArchSection};
use skladiste::manifest::Hash;
use skladiste::{install, store::Store, worker::Workers};
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

fn workers() -> Workers {
    Workers::new(env!("CARGO_BIN_EXE_skl"))
}

/// Build the image `img`, whose parent directory exists.
fn build(store: &Store, pkgs: &[Hash], img: &Path) -> anyhow::Result<install::Report> {
    let parent = File::open(img.parent().unwrap()).unwrap();
    let name = img.file_name().unwrap();
    install::build(&workers(), store, pkgs, parent.as_fd(), name)
}

/// Import the package file at `path`, returning the package's id.
fn import(store: &Store, path: &Path) -> Hash {
    let pkg = arch::import(&workers(), store, File::open(path).unwrap())
        .unwrap()
        .0;
    store.add_package(&pkg).unwrap()
}

#[test]
fn build_image() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
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
    let (tools, stats) = arch::import(&workers(), &store, File::open(&tools).unwrap()).unwrap();
    assert_eq!(stats.files, 4);
    assert_eq!(stats.new_blobs, 3, "identical files share one blob");
    let tools = store.add_package(&tools).unwrap();

    let img = tmp.path().join("img");
    let report = build(&store, &[base, tools], &img).unwrap();
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
fn install_scriptlets_are_kept() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
    let script = b"post_install() {\n\ttrue\n}\n";
    let path = make_package(
        tmp.path(),
        "scripted",
        &[
            Item::File(".INSTALL", 0o644, script),
            Item::Dir("etc/", 0o755),
        ],
    );
    let id = import(&store, &path);
    let pkg = store.load_package(&id).unwrap();
    assert_eq!(pkg.entries.len(), 1, "metadata files aren't entries");
    let section = ArchSection::of(&pkg).unwrap();
    let blob = pkg.sections[arch::SECTION]
        .blob(section.install.unwrap())
        .unwrap();
    let file = File::from(store.open_blob(blob).unwrap());
    assert_eq!(std::io::read_to_string(file).unwrap().as_bytes(), script);
    // Importing again gives the same id.
    assert_eq!(import(&store, &path), id);
}

#[test]
fn overlays_change_earlier_packages() {
    use skladiste::manifest::{Content, Entry, EntryKind, Overlay, Package};
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
    let base = make_package(
        tmp.path(),
        "base",
        &[
            Item::Dir("etc/", 0o755),
            Item::File("etc/conf", 0o644, b"old"),
            Item::File("etc/gone", 0o644, b"x"),
            Item::Dir("var/", 0o755),
            Item::Dir("var/lib/", 0o755),
            Item::File("var/lib/f", 0o644, b"f"),
        ],
    );
    let base = import(&store, &base);
    let added = store.add_blob(&mut &b"new"[..]).unwrap();
    let entry = |path: &str, kind| Entry {
        path: path.into(),
        kind,
        mode: 0o600,
        uid: 0,
        gid: 0,
        mtime: 5,
        xattrs: Default::default(),
    };
    let content = Content {
        hash: added.hash,
        size: added.size,
    };
    let overlay = Package {
        name: "@test/overlay".into(),
        version: String::new(),
        entries: vec![
            entry("etc/conf", EntryKind::File(content)),
            entry(
                "etc/link",
                EntryKind::Hardlink {
                    target: "etc/conf".into(),
                },
            ),
            // A directory replaced by a symlink, with its contents.
            entry(
                "var/lib",
                EntryKind::Symlink {
                    target: "/elsewhere".into(),
                },
            ),
        ],
        sections: Default::default(),
        overlay: Some(Overlay {
            removed: vec!["etc/gone".into()],
        }),
    };
    let overlay = store.add_package(&overlay).unwrap();
    let img = tmp.path().join("img");
    build(&store, &[base, overlay], &img).unwrap();
    assert_eq!(fs::read(img.join("etc/conf")).unwrap(), b"new");
    let conf = fs::metadata(img.join("etc/conf")).unwrap();
    assert_eq!(
        (conf.permissions().mode() & 0o777, conf.nlink()),
        (0o600, 2)
    );
    assert!(!img.join("etc/gone").exists());
    assert_eq!(
        fs::read_link(img.join("var/lib")).unwrap(),
        Path::new("/elsewhere")
    );
    // An overlay's changes need the packages before it.
    let e = build(&store, &[overlay], &tmp.path().join("img2")).unwrap_err();
    assert!(format!("{e:#}").contains("/etc"), "{e:#}");
}

#[test]
fn conflicting_files_are_rejected() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
    let a = make_package(tmp.path(), "a", &[Item::File("f", 0o644, b"a")]);
    let b = make_package(tmp.path(), "b", &[Item::File("f", 0o644, b"b")]);
    let pkgs = [import(&store, &a), import(&store, &b)];
    let err = build(&store, &pkgs, &tmp.path().join("img")).unwrap_err();
    assert!(err.to_string().contains("conflict: /f"), "{err}");
}

#[test]
fn worker_errors_are_reported() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
    let path = tmp.path().join("bad.pkg.tar.zst");
    fs::write(&path, "not an archive").unwrap();
    let err = arch::import(&workers(), &store, File::open(&path).unwrap()).unwrap_err();
    assert!(
        err.to_string().contains("unsupported compression"),
        "{err:#}"
    );
}

#[test]
fn concurrent_imports_share_blobs() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let store = Store::init_path(&tmp.path().join("store")).unwrap();
    let files: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_le_bytes().repeat(100)).collect();
    let items: Vec<(String, &[u8])> = files
        .iter()
        .enumerate()
        .map(|(i, data)| (format!("f{i}"), data.as_slice()))
        .collect();
    let items: Vec<Item> = items
        .iter()
        .map(|(p, data)| Item::File(p, 0o644, data))
        .collect();
    let path = make_package(tmp.path(), "same", &items);

    let workers = workers();
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..4)
            .map(|_| s.spawn(|| arch::import(&workers, &store, File::open(&path).unwrap())))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut new_blobs = 0;
    for r in results {
        let (pkg, stats) = r.unwrap();
        assert_eq!(pkg.entries.len(), 200);
        assert_eq!(stats.files, 200);
        new_blobs += stats.new_blobs;
    }
    assert_eq!(new_blobs, 200, "each blob is new for one import only");
}
