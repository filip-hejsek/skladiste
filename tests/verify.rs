//! Signature verification through the sandboxed `verify-arch` workers, with
//! a generated keyring. The rules themselves are tested in
//! `arch::signature`.

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
use skladiste::arch::verify::{KeyringError, KeyringFiles, with_verifier};
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
