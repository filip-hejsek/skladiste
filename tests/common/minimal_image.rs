//! A minimal image to run the current test binary in, for tests of
//! sandboxed programs. Shared by the unit tests of `src/run.rs` and the
//! integration tests.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Where the test binary is in the image.
pub(crate) const CHILD: &str = "/child";

/// Whether this process is the test binary running in the image.
pub(crate) fn is_child() -> bool {
    std::env::current_exe().unwrap() == Path::new(CHILD)
}

/// Arguments for the test binary to run only `test` (its full path, e.g.
/// `run::tests::name`).
pub(crate) fn child_args(test: &str) -> Vec<OsString> {
    ["--exact", test, "--nocapture"]
        .iter()
        .map(OsString::from)
        .collect()
}

/// Fill `root` with what the test binary needs to run: the binary at
/// [`CHILD`], its dynamic loader, the libraries it has mapped, the host's
/// `/lib*` symlinks and `ld.so.cache`, and empty directories for the mount
/// points of the sandbox (so it doesn't create them).
pub(crate) fn populate(root: &Path) {
    let copy = |from: &Path, to: &str| {
        let dest = root.join(to.trim_start_matches('/'));
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(from, dest).unwrap();
    };
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let child = root.join(&CHILD[1..]);
    std::fs::write(&child, &exe).unwrap();
    std::fs::set_permissions(&child, PermissionsExt::from_mode(0o755)).unwrap();
    let interp = interpreter(&exe);
    copy(Path::new(interp), interp);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let libs = maps
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .filter(|p| p.starts_with("/usr/") || p.starts_with("/lib"));
    for lib in libs {
        copy(Path::new(lib), lib);
    }
    if Path::new("/etc/ld.so.cache").exists() {
        copy(Path::new("/etc/ld.so.cache"), "/etc/ld.so.cache");
    }
    for dir in ["/lib", "/lib32", "/lib64", "/libx32"] {
        if let Ok(target) = std::fs::read_link(dir) {
            let dest = root.join(&dir[1..]);
            if !dest.exists() {
                std::os::unix::fs::symlink(target, dest).unwrap();
            }
        }
    }
    for dir in ["proc", "dev", "tmp", "run"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
}

/// The `PT_INTERP` path of a 64-bit ELF executable.
fn interpreter(elf: &[u8]) -> &str {
    let u16_at = |o: usize| u16::from_ne_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u64_at = |o: usize| u64::from_ne_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
    let (phoff, phentsize, phnum) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
    for ph in (0..phnum).map(|i| phoff + i * phentsize) {
        if u32::from_ne_bytes(elf[ph..ph + 4].try_into().unwrap()) == 3 {
            let (off, len) = (u64_at(ph + 8), u64_at(ph + 32));
            let path = &elf[off..off + len];
            return std::str::from_utf8(path.strip_suffix(b"\0").unwrap()).unwrap();
        }
    }
    panic!("no PT_INTERP");
}
