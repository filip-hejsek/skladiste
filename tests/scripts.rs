//! Building an image with package code: install scriptlets and hooks run,
//! and what they change is kept as a synthetic package and reused.
//! Skipped when the cargo target directory is not on btrfs.

use std::fs::{self, File};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use skladiste::arch::scripts::{self, Code, SYNTHETIC_NAME, ScriptsSection};
use skladiste::arch::{self, SECTION};
use skladiste::manifest::Hash;
use skladiste::store::Store;
use skladiste::worker::Workers;
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

fn workers() -> Workers {
    Workers::new(env!("CARGO_BIN_EXE_skl"))
}

/// What goes into a test package.
enum Item {
    Dir(String),
    File(String, u32, Vec<u8>),
    Symlink(String, String),
}

/// Write the package `name` (version 1-1) with `.PKGINFO` lines `info`.
fn make_package(dir: &Path, name: &str, info: &str, items: &[Item]) -> PathBuf {
    let path = dir.join(format!("{name}-1-1-any.pkg.tar.zst"));
    let enc = zstd::Encoder::new(File::create(&path).unwrap(), 3).unwrap();
    let mut b = tar::Builder::new(enc);
    let pkginfo = format!("pkgname = {name}\npkgver = 1-1\n{info}");
    let mut h = Header::new_gnu();
    h.set_size(pkginfo.len() as u64);
    h.set_mode(0o644);
    b.append_data(&mut h, ".PKGINFO", pkginfo.as_bytes())
        .unwrap();
    for item in items {
        let mut h = Header::new_gnu();
        h.set_mtime(1_000_000);
        h.set_uid(0);
        h.set_gid(0);
        match item {
            Item::Dir(p) => {
                h.set_entry_type(EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                b.append_data(&mut h, format!("{p}/"), &[][..]).unwrap();
            }
            Item::File(p, mode, data) => {
                h.set_mode(*mode);
                h.set_size(data.len() as u64);
                b.append_data(&mut h, p, &data[..]).unwrap();
            }
            Item::Symlink(p, target) => {
                h.set_entry_type(EntryType::Symlink);
                h.set_mode(0o777);
                h.set_size(0);
                b.append_link(&mut h, p, target).unwrap();
            }
        }
    }
    b.into_inner().unwrap().finish().unwrap();
    path
}

/// The host's bash with what it needs to run, as items of a package:
/// `/bin/sh` for package code.
fn shell_items() -> Vec<Item> {
    let mut files = vec!["/usr/bin/bash".to_owned()];
    let ldd = Command::new("ldd").arg("/usr/bin/bash").output().unwrap();
    for line in String::from_utf8(ldd.stdout).unwrap().lines() {
        let path = match line.split_once("=> ") {
            Some((_, rest)) => rest.split(' ').next().unwrap(),
            None => line.trim().split(' ').next().unwrap(),
        };
        if path.starts_with('/') {
            files.push(path.to_owned());
        }
    }
    let mut dirs = std::collections::BTreeSet::new();
    let mut items = Vec::new();
    for file in files {
        let real = fs::canonicalize(&file).unwrap();
        for p in [Path::new(&file), real.as_path()] {
            let rel = p.strip_prefix("/").unwrap();
            for d in rel.ancestors().skip(1) {
                if !d.as_os_str().is_empty() {
                    dirs.insert(d.to_str().unwrap().to_owned());
                }
            }
        }
        let rel = real.strip_prefix("/").unwrap().to_str().unwrap().to_owned();
        if Path::new(&file) != real {
            let link = file.trim_start_matches('/').to_owned();
            if !items
                .iter()
                .any(|i| matches!(i, Item::Symlink(p, _) if *p == link))
            {
                items.push(Item::Symlink(link, real.to_str().unwrap().to_owned()));
            }
        }
        if !items
            .iter()
            .any(|i| matches!(i, Item::File(p, ..) if *p == rel))
        {
            items.push(Item::File(rel, 0o755, fs::read(&real).unwrap()));
        }
    }
    // Directories that are symlinks on the host (e.g. /lib64 -> usr/lib)
    // stay symlinks.
    let mut out: Vec<Item> = Vec::new();
    for d in dirs {
        let host = Path::new("/").join(&d);
        match fs::read_link(&host) {
            Ok(target) => out.push(Item::Symlink(d, target.to_str().unwrap().to_owned())),
            Err(_) => out.push(Item::Dir(d)),
        }
    }
    let linked: Vec<String> = out
        .iter()
        .filter_map(|i| match i {
            Item::Symlink(p, _) => Some(format!("{p}/")),
            _ => None,
        })
        .collect();
    // Items beneath a symlinked directory are installed through it, but
    // must not be listed under both names.
    items.retain(|i| match i {
        Item::File(p, ..) | Item::Symlink(p, _) => !linked.iter().any(|l| p.starts_with(l)),
        Item::Dir(_) => true,
    });
    out.extend(items);
    out.push(Item::Symlink("usr/bin/sh".into(), "bash".into()));
    // The host's /bin and /lib* symlinks (the dynamic loader's path may be
    // through one), as in the minimal image of the run tests.
    for d in ["bin", "lib", "lib32", "lib64", "libx32"] {
        if let Ok(target) = fs::read_link(Path::new("/").join(d)) {
            out.push(Item::Symlink(d.into(), target.to_str().unwrap().into()));
        }
    }
    out.push(Item::Dir("etc".into()));
    out
}

const HOOK: &str = "[Trigger]\nOperation = Install\nType = Path\nTarget = etc/app/*\n\
    Target = !etc/app/skip\n\n[Action]\nDescription = Listing the targets\n\
    Exec = /bin/sh -c 'while read -r l; do echo \"$l\"; done > /etc/hook-targets'\n\
    When = PostTransaction\nNeedsTargets\n";

/// Build the image `name` in `dir` from `ids`.
fn build(store: &Store, dir: &Path, name: &str, ids: &[Hash], rerun: bool) -> Code {
    let parent = File::open(dir).unwrap();
    scripts::build(&workers(), store, ids, parent.as_fd(), name.as_ref(), rerun)
        .unwrap()
        .code
}

fn import(store: &Store, path: &Path) -> Hash {
    let pkg = arch::import(&workers(), store, File::open(path).unwrap())
        .unwrap()
        .0;
    store.add_package(&pkg).unwrap()
}

#[test]
fn package_code_runs_once() {
    let Some(tmp) = btrfs_tempdir() else { return };
    let dir = tmp.path();
    let store = Store::init_path(&dir.join("store")).unwrap();
    let base = make_package(dir, "base", "", &shell_items());
    let install = b"post_install() {\n\techo \"$1\" > /etc/app-version\n\
        \tprintf 'escaped: \\033[31m\\n'\n}\n\
        pre_install() {\n\ttest ! -e /etc/app-version && echo pre > /etc/app-pre\n}\n";
    let app = make_package(
        dir,
        "app",
        "depend = base\n",
        &[
            Item::File(".INSTALL".into(), 0o644, install.to_vec()),
            Item::Dir("etc/app".into()),
            Item::File("etc/app/a".into(), 0o644, b"a".to_vec()),
            Item::File("etc/app/skip".into(), 0o644, b"s".to_vec()),
            Item::Dir("usr/share".into()),
            Item::Dir("usr/share/libalpm".into()),
            Item::Dir("usr/share/libalpm/hooks".into()),
            Item::File(
                "usr/share/libalpm/hooks/app.hook".into(),
                0o644,
                HOOK.as_bytes().to_vec(),
            ),
        ],
    );
    let (base, app) = (import(&store, &base), import(&store, &app));
    // Given in the wrong order: base goes first, as app depends on it.
    let ids = [app, base];
    let Code::Ran(ran) = build(&store, dir, "img", &ids, false) else {
        panic!("no code ran");
    };
    assert!(ran.status.success(), "{:?}", ran.status);
    assert_eq!((ran.scripts, ran.hooks), (1, 1));
    let img = dir.join("img");
    assert_eq!(
        fs::read_to_string(img.join("etc/app-version")).unwrap(),
        "1-1\n"
    );
    assert_eq!(
        fs::read_to_string(img.join("etc/app-pre")).unwrap(),
        "pre\n"
    );
    assert_eq!(
        fs::read_to_string(img.join("etc/hook-targets")).unwrap(),
        "etc/app/\netc/app/a\n"
    );
    let synthetic = store.load_package(&ran.synthetic).unwrap();
    assert_eq!(synthetic.name, SYNTHETIC_NAME);
    assert!(synthetic.overlay.is_some());
    let section: ScriptsSection =
        serde_json::from_value(synthetic.sections[SECTION].value.clone()).unwrap();
    assert_eq!(section.scripts, ["app"]);
    assert_eq!(section.hooks, ["app.hook"]);
    let paths: Vec<&str> = synthetic.entries.iter().map(|e| e.path.as_str()).collect();
    // The mount points of the sandbox, which no package has here, are
    // changes too.
    assert_eq!(
        paths,
        [
            "dev",
            "etc",
            "etc/app-pre",
            "etc/app-version",
            "etc/hook-targets",
            "proc",
            "run",
            "tmp"
        ]
    );

    // The same packages again: the synthetic package is installed.
    let reused = build(&store, dir, "img2", &ids, false);
    assert!(
        matches!(reused, Code::Reused(id) if id == ran.synthetic),
        "{reused:?}"
    );
    let img2 = dir.join("img2");
    for f in ["etc/app-version", "etc/hook-targets"] {
        assert_eq!(
            fs::read(img.join(f)).unwrap(),
            fs::read(img2.join(f)).unwrap()
        );
    }
    // Unless asked to run the code again.
    let rerun = build(&store, dir, "img3", &ids, true);
    assert!(matches!(rerun, Code::Ran(_)), "{rerun:?}");
    // Packages without code have none to run.
    let none = build(&store, dir, "img4", &[base], false);
    assert!(matches!(none, Code::None), "{none:?}");
}
