//! Signature verification through the sandboxed `verify-arch` workers, with
//! a generated keyring, and the keyring kept in the store. The rules
//! themselves are tested in `arch::signature`.

use std::fs::File;
use std::io::{Seek, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use sequoia_openpgp::Cert;
use sequoia_openpgp::Packet;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::types::SignatureType;
use skladiste::arch::keyring::{self, NoKeyring, Outcome};
use skladiste::arch::packages::{self, Context, LocalFile, LocalPackage};
use skladiste::arch::repo::LOCAL_REPO;
use skladiste::arch::verify::{KeyringError, KeyringFiles, with_verifier};
use skladiste::manifest::Hash;
use skladiste::store::{Store, gc};
use skladiste::worker::Workers;

static POLICY: StandardPolicy = StandardPolicy::new();

fn workers() -> Workers {
    Workers::new(env!("CARGO_BIN_EXE_skl"))
}

fn new_cert(name: &str) -> Cert {
    CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_creation_time(SystemTime::now() - Duration::from_secs(100))
        .add_userid(format!("{name} <{name}@example.org>"))
        .add_signing_subkey()
        .generate()
        .unwrap()
        .0
}

fn certify(master: &Cert, cert: Cert) -> Cert {
    let mut signer = master
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let userid = cert.userids().next().unwrap().userid().clone();
    let sig = SignatureBuilder::new(SignatureType::GenericCertification)
        .set_signature_creation_time(SystemTime::now() - Duration::from_secs(50))
        .unwrap()
        .sign_userid_binding(&mut signer, cert.primary_key().key(), &userid)
        .unwrap();
    cert.insert_packets(sig).unwrap().0
}

/// A signature made now. Signatures must be made before the keyring is
/// loaded: validity is evaluated as of then.
fn sign(cert: &Cert, data: &[u8]) -> Vec<u8> {
    sign_at(cert, data, SystemTime::now())
}

fn sign_at(cert: &Cert, data: &[u8], t: SystemTime) -> Vec<u8> {
    let key = cert
        .keys()
        .subkeys()
        .with_policy(&POLICY, None)
        .for_signing()
        .next()
        .unwrap();
    let mut signer = key
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let sig = SignatureBuilder::new(SignatureType::Binary)
        .set_signature_creation_time(t)
        .unwrap()
        .sign_message(&mut signer, data)
        .unwrap();
    Packet::from(sig).to_vec().unwrap()
}

/// Three master keys and a packager key they certify, written as keyring
/// files to `dir`.
struct Setup {
    packager: Cert,
    other: Cert,
}

fn setup(dir: &Path) -> Setup {
    let masters: Vec<Cert> = (0..3).map(|i| new_cert(&format!("master{i}"))).collect();
    let mut packager = new_cert("packager");
    for m in &masters {
        packager = certify(m, packager);
    }
    let mut gpg = Vec::new();
    let mut trusted = String::new();
    for m in &masters {
        gpg.extend(m.to_vec().unwrap());
        trusted += &format!("{}:4:\n", m.fingerprint().to_hex());
    }
    gpg.extend(packager.to_vec().unwrap());
    std::fs::write(dir.join("keyring.gpg"), gpg).unwrap();
    std::fs::write(dir.join("keyring-trusted"), trusted).unwrap();
    std::fs::write(dir.join("keyring-revoked"), "").unwrap();
    Setup {
        packager,
        other: new_cert("other"),
    }
}

fn keyring(dir: &Path) -> KeyringFiles {
    let open = |name: &str| File::open(dir.join(name)).unwrap();
    KeyringFiles {
        certs: open("keyring.gpg"),
        trusted: open("keyring-trusted"),
        revoked: open("keyring-revoked"),
    }
}

/// A file in `dir` with `data`, open for reading and writing, with its
/// offset at the end (the verifier reads from the start regardless).
fn archive(dir: &Path, name: &str, data: &[u8]) -> File {
    let mut file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.join(name))
        .unwrap();
    file.write_all(data).unwrap();
    file
}

#[test]
fn verifies_in_worker() {
    let dir = tempfile::tempdir().unwrap();
    let s = setup(dir.path());
    let data = b"package contents".repeat(10_000);
    let file = archive(dir.path(), "a.pkg", &data);
    let good = sign(&s.packager, &data);
    let unknown = sign(&s.other, &data);
    let modified = sign(&s.packager, b"other");
    let future = sign_at(
        &s.packager,
        &data,
        SystemTime::now() + Duration::from_secs(3600),
    );
    with_verifier(&workers(), keyring(dir.path()), 2, |v| {
        v.verify(&good, &file)?;
        // A bad verdict doesn't end the worker; the next one is good.
        let err = |sig: &[u8]| format!("{:#}", v.verify(sig, &file).unwrap_err());
        let e = err(&unknown);
        assert!(e.contains("not in the keyring"), "{e}");
        let e = err(&modified);
        assert!(e.contains("bad signature"), "{e}");
        // The message has a time in it, formatted with glibc's strftime,
        // which loads the time zone on first use.
        let e = err(&future);
        assert!(e.contains("not alive"), "{e}");
        let e = err(b"garbage");
        assert!(e.contains("reading signature"), "{e}");
        let e = err(&vec![0; 1 << 20]);
        assert!(e.contains("too large"), "{e}");
        v.verify(&good, &file)?;
        // The file's own offset is left alone.
        assert_eq!(
            (&file).stream_position()?,
            data.len() as u64,
            "offset changed"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn verifies_from_many_threads() {
    let dir = tempfile::tempdir().unwrap();
    let s = setup(dir.path());
    let files: Vec<(Vec<u8>, File)> = (0..12)
        .map(|i| {
            let data = format!("package {i}").repeat(1000).into_bytes();
            let file = archive(dir.path(), &format!("{i}.pkg"), &data);
            (sign(&s.packager, &data), file)
        })
        .collect();
    with_verifier(&workers(), keyring(dir.path()), 3, |v| {
        // Threads that start workers end before others use them.
        for chunk in files.chunks(4) {
            std::thread::scope(|scope| {
                let threads: Vec<_> = chunk
                    .iter()
                    .map(|(sig, file)| scope.spawn(|| v.verify(sig, file)))
                    .collect();
                for t in threads {
                    t.join().unwrap().unwrap();
                }
            });
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn bad_keyring_fails_first() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    std::fs::write(dir.path().join("keyring-trusted"), "nothex:4:\n").unwrap();
    let mut ran = false;
    let e = with_verifier(&workers(), keyring(dir.path()), 1, |_| {
        ran = true;
        Ok(())
    })
    .unwrap_err();
    assert!(!ran);
    assert!(e.is::<KeyringError>(), "{e:#}");
    assert!(format!("{e:#}").contains("master key list"), "{e:#}");
}

/// Write an `archlinux-keyring`-like package `name` of `version` with the
/// keyring files in `keyring`, and its signature by `signer`, to `dir`;
/// returns the package's file name.
fn keyring_package(dir: &Path, name: &str, version: &str, keyring: &Path, signer: &Cert) -> String {
    let mut b = tar::Builder::new(zstd::Encoder::new(Vec::new(), 3).unwrap());
    let pkginfo = format!("pkgname = {name}\npkgver = {version}\n");
    let mut files = vec![(".PKGINFO".to_owned(), pkginfo.into_bytes())];
    for (file, path) in [
        ("keyring.gpg", "archlinux.gpg"),
        ("keyring-trusted", "archlinux-trusted"),
        ("keyring-revoked", "archlinux-revoked"),
    ] {
        let data = std::fs::read(keyring.join(file)).unwrap();
        files.push((format!("usr/share/pacman/keyrings/{path}"), data));
    }
    for (path, data) in files {
        let mut h = tar::Header::new_ustar();
        h.set_mtime(1_000_000);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        b.append_data(&mut h, path, data.as_slice()).unwrap();
    }
    let archive = b.into_inner().unwrap().finish().unwrap();
    let file = format!("{name}-{version}-any.pkg.tar.zst");
    std::fs::write(dir.join(&file), &archive).unwrap();
    std::fs::write(dir.join(format!("{file}.sig")), sign(signer, &archive)).unwrap();
    file
}

/// Import the package file `name` in `dir` into `@local`, verified with
/// the store's keyring, returning the package's id.
fn import_local(store: &Store, dir: &Path, name: &str) -> anyhow::Result<Hash> {
    let workers = workers();
    let path = dir.join(name);
    let sig = dir.join(format!("{name}.sig"));
    let before = store.package_index(LOCAL_REPO)?;
    keyring::with_verifier(&workers, store, 1, |verifier| {
        let ctx = Context {
            workers: &workers,
            store,
            verifier,
            jobs: 1.try_into().unwrap(),
            report: &|_| {},
        };
        let file = LocalFile {
            name: name.to_owned(),
            size: 0,
            open: Box::new(move || Ok((File::open(&path)?, File::open(&sig)?))),
        };
        packages::import_local(&ctx, vec![LocalPackage::File(file)])
    })?;
    let after = store.package_index(LOCAL_REPO)?;
    Ok(after.into_iter().find(|e| !before.contains(e)).unwrap().1)
}

/// Check `signature` of `data` with the store's keyring.
fn store_verifies(store: &Store, signature: &[u8], data: &[u8]) -> anyhow::Result<()> {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    keyring::with_verifier(&workers(), store, 1, |v| v.verify(signature, &file))
}

#[test]
fn keyring_in_store() {
    let dir = tempfile::tempdir().unwrap();
    let [old_dir, new_dir, store_dir] = ["old", "new", "store"].map(|d| dir.path().join(d));
    for d in [&old_dir, &new_dir, &store_dir] {
        std::fs::create_dir(d).unwrap();
    }
    let old = setup(&old_dir);
    let new = setup(&new_dir);
    let store = Store::init_path(&store_dir).unwrap();
    let w = workers();
    let data = b"package";

    let e = store_verifies(&store, b"", data).unwrap_err();
    assert!(e.is::<NoKeyring>(), "{e:#}");

    // Files the user gives; giving them again changes nothing.
    match keyring::init(&w, &store, keyring(&old_dir)).unwrap() {
        Outcome::Set { old: None, new } => assert_eq!(new.package, None),
        other => panic!("{other:?}"),
    }
    let first = keyring::current(&store).unwrap().unwrap();
    let outcome = keyring::init(&w, &store, keyring(&old_dir)).unwrap();
    assert_eq!(outcome, Outcome::Unchanged(first.1.clone()));

    // The GC keeps the keyring's record and blobs.
    drop(store);
    let exclusive = Store::open_exclusive_path(&store_dir).unwrap();
    exclusive.gc(&gc::Options::default()).unwrap();
    drop(exclusive);
    let store = Store::open_path(&store_dir).unwrap();
    assert_eq!(keyring::current(&store).unwrap().unwrap(), first);
    store_verifies(&store, &sign(&old.packager, data), data).unwrap();
    let e = store_verifies(&store, &sign(&new.packager, data), data).unwrap_err();
    assert!(format!("{e:#}").contains("not in the keyring"), "{e:#}");

    // An update from a package signed by a key of the store's keyring.
    let pkgs = dir.path();
    let file = keyring_package(
        pkgs,
        "archlinux-keyring",
        "20260101-1",
        &new_dir,
        &old.packager,
    );
    let id = import_local(&store, pkgs, &file).unwrap();
    match keyring::update(&w, &store, &id).unwrap() {
        Outcome::Set { old: Some(o), new } => {
            assert_eq!(o, first.1);
            let from = new.package.unwrap();
            assert_eq!((from.id, from.version.as_str()), (id, "20260101-1"));
        }
        other => panic!("{other:?}"),
    }
    store_verifies(&store, &sign(&new.packager, data), data).unwrap();
    let e = store_verifies(&store, &sign(&old.packager, data), data).unwrap_err();
    assert!(format!("{e:#}").contains("not in the keyring"), "{e:#}");
    // The same version again changes nothing.
    let current = keyring::current(&store).unwrap().unwrap().1;
    let outcome = keyring::update(&w, &store, &id).unwrap();
    assert_eq!(outcome, Outcome::Unchanged(current.clone()));

    // An older version is refused, though its signature is good.
    let file = keyring_package(
        pkgs,
        "archlinux-keyring",
        "20250101-1",
        &old_dir,
        &new.packager,
    );
    let older = import_local(&store, pkgs, &file).unwrap();
    let e = keyring::update(&w, &store, &older).unwrap_err();
    assert!(format!("{e:#}").contains("older"), "{e:#}");
    // So is a package of another name.
    let file = keyring_package(pkgs, "other-keyring", "20270101-1", &old_dir, &new.packager);
    let other = import_local(&store, pkgs, &file).unwrap();
    let e = keyring::update(&w, &store, &other).unwrap_err();
    assert!(format!("{e:#}").contains("not archlinux-keyring"), "{e:#}");
    assert_eq!(keyring::current(&store).unwrap().unwrap().1, current);

    // Files that don't load as a keyring aren't set.
    std::fs::write(old_dir.join("keyring-trusted"), "nothex:4:\n").unwrap();
    let e = keyring::init(&w, &store, keyring(&old_dir)).unwrap_err();
    assert!(format!("{e:#}").contains("master key list"), "{e:#}");
    assert_eq!(keyring::current(&store).unwrap().unwrap().1, current);
}
