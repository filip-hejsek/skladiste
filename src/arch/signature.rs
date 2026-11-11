//! Verification of Arch package signatures against the Arch keyring
//! (`archlinux-keyring`).
//!
//! The keyring has three parts: the certificates (`archlinux.gpg`), the
//! fingerprints of the master keys (`archlinux-trusted`), and fingerprints
//! of keys that must not be used (`archlinux-revoked`). pacman imports them
//! into GnuPG and leaves the decision to its web of trust; skl checks the
//! rule that this amounts to directly: a package is signed by a packager
//! key, and a packager key is one with a user ID certified by at least
//! [`REQUIRED_CERTIFICATIONS`] master keys.
//!
//! Everything is evaluated at the time the keyring is loaded, as GnuPG
//! does: master keys, the packager key, its signing key and the
//! certifications must be valid then (alive, not revoked, not listed as
//! revoked by primary key fingerprint). Not as of the signature's creation
//! time: the Arch keyring keeps only the latest self-signatures, so a key
//! often has no valid binding as of when an older package was signed. The
//! signing key must predate the signature. Weak algorithms are rejected by
//! Sequoia's standard policy.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{BufRead, ErrorKind, Read};
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::cert::{CertParser, ValidCert};
use sequoia_openpgp::crypto::hash::Context as HashContext;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::types::{RevocationStatus, RevocationType, SignatureType};
use sequoia_openpgp::{Cert, Fingerprint, KeyID, Packet, PacketPile};

/// Number of master keys that must have certified a packager key, as with
/// GnuPG's default `marginals-needed` and the master keys' marginal owner
/// trust in `archlinux-trusted`.
pub const REQUIRED_CERTIFICATIONS: usize = 3;

/// Owner trust level of master keys in `archlinux-trusted` (marginal).
const MASTER_TRUST_LEVEL: &str = "4";

/// Largest signature file accepted. Arch signatures are a few hundred bytes.
pub const MAX_SIGNATURE_SIZE: u64 = 64 << 10;

/// Most signatures accepted in one signature file; the data is hashed once
/// for each.
const MAX_SIGNATURES: usize = 8;

static POLICY: StandardPolicy = StandardPolicy::new();

/// The Arch keyring. Which certificates are packager keys is worked out
/// when one of them signs something, as checking certifications of the
/// whole keyring takes a few hundred milliseconds.
pub struct Keyring {
    /// Certificates not listed as revoked.
    certs: Vec<Cert>,
    /// Indices into `certs` by the key ID of each of their keys.
    by_key_id: HashMap<KeyID, Vec<usize>>,
    /// Indices into `certs` of usable master keys.
    masters: Vec<usize>,
    /// For each certificate, the number of master keys certifying it (the
    /// most for any of its user IDs), once needed.
    certifications: Vec<OnceLock<usize>>,
    /// Time at which validity is evaluated: when the keyring was loaded.
    now: SystemTime,
}

impl Keyring {
    /// Load a keyring from its three files: OpenPGP certificates (binary or
    /// armored), master key fingerprints (`FINGERPRINT:4:` lines), and
    /// revoked key fingerprints (one per line). Fails if fewer than
    /// [`REQUIRED_CERTIFICATIONS`] master keys are usable.
    pub fn load(
        certs: impl Read + Send + Sync,
        trusted: impl BufRead,
        revoked: impl BufRead,
    ) -> Result<Keyring> {
        let trusted = parse_trusted(trusted).context("reading master key list")?;
        let revoked = parse_revoked(revoked).context("reading revoked key list")?;
        let mut kept = Vec::new();
        for cert in CertParser::from_reader(certs).context("reading certificates")? {
            let cert = cert.context("reading certificates")?;
            if !revoked.contains(&cert.fingerprint()) {
                kept.push(cert);
            }
        }
        let now = SystemTime::now();
        let masters: Vec<usize> = (0..kept.len())
            .filter(|&i| trusted.contains(&kept[i].fingerprint()))
            .filter(|&i| {
                usable(&kept[i], now).is_some_and(|vc| vc.primary_key().for_certification())
            })
            .collect();
        if masters.len() < REQUIRED_CERTIFICATIONS {
            bail!(
                "{} usable master keys, {REQUIRED_CERTIFICATIONS} needed",
                masters.len()
            );
        }
        let mut by_key_id: HashMap<KeyID, Vec<usize>> = HashMap::new();
        for (i, cert) in kept.iter().enumerate() {
            for key in cert.keys() {
                by_key_id.entry(key.key().keyid()).or_default().push(i);
            }
        }
        Ok(Keyring {
            certifications: kept.iter().map(|_| OnceLock::new()).collect(),
            certs: kept,
            by_key_id,
            masters,
            now,
        })
    }

    /// Number of master keys certifying `certs[i]`.
    fn certifications(&self, i: usize) -> usize {
        *self.certifications[i].get_or_init(|| {
            let masters: Vec<ValidCert> = self
                .masters
                .iter()
                .filter(|&&m| m != i)
                .filter_map(|&m| usable(&self.certs[m], self.now))
                .collect();
            count_certifications(&self.certs[i], &masters, self.now)
        })
    }

    /// Check a detached signature (`.sig` file contents) of `data`. Succeeds
    /// if at least one of the signatures in it is a valid signature by a
    /// packager key; returns that key's fingerprint. `data` is read once.
    pub fn verify(&self, signature: &[u8], mut data: impl Read) -> Result<Fingerprint> {
        let pile = PacketPile::from_bytes(signature).context("reading signature")?;
        let mut sigs = Vec::new();
        for packet in pile.into_children() {
            match packet {
                Packet::Signature(sig) => sigs.push(sig),
                Packet::Unknown(u) => bail!("unsupported signature: {}", u.error()),
                p => bail!("unexpected {} packet in signature", p.tag()),
            }
        }
        if sigs.is_empty() {
            bail!("no signatures");
        }
        if sigs.len() > MAX_SIGNATURES {
            bail!("more than {MAX_SIGNATURES} signatures");
        }
        let mut hashes = Vec::new();
        for sig in &sigs {
            if sig.typ() != SignatureType::Binary {
                bail!("unsupported signature type {}", sig.typ());
            }
            let mut hash = sig.hash_algo().context()?.for_signature(sig.version());
            if let Some(salt) = sig.salt() {
                hash.update(salt);
            }
            hashes.push(hash);
        }
        let mut buf = vec![0; 64 << 10];
        loop {
            let n = match data.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("reading package"),
            };
            for hash in &mut hashes {
                hash.update(&buf[..n]);
            }
        }
        let mut problems = Vec::new();
        for (sig, hash) in sigs.iter().zip(hashes) {
            match self.check(sig, hash) {
                Ok(fpr) => return Ok(fpr),
                Err(e) => problems.push(format!("{e:#}")),
            }
        }
        bail!(
            "no valid signature by a packager key: {}",
            problems.join("; ")
        )
    }

    /// Check one signature, given the hash of the data.
    fn check(&self, sig: &Signature, hash: HashContext) -> Result<Fingerprint> {
        let now = self.now;
        POLICY
            .signature(sig, Default::default())
            .context("signature rejected by policy")?;
        sig.signature_alive(now, None)
            .context("signature not alive")?;
        let issuers = sig.get_issuers();
        let mut certs = BTreeSet::new();
        for issuer in &issuers {
            if let Some(indices) = self.by_key_id.get(&KeyID::from(issuer)) {
                certs.extend(indices.iter().copied());
            }
        }
        if certs.is_empty() {
            let issuers: Vec<String> = issuers.iter().map(|h| h.to_string()).collect();
            bail!(
                "signed by a key not in the keyring ({})",
                issuers.join(", ")
            );
        }
        let mut problems = Vec::new();
        for i in certs {
            let cert = &self.certs[i];
            let fpr = cert.fingerprint();
            let who = format!("{fpr}{}", describe(cert));
            let Some(vc) = usable(cert, now) else {
                problems.push(format!("{who} is expired, revoked or invalid"));
                continue;
            };
            let n = self.certifications(i);
            if n < REQUIRED_CERTIFICATIONS {
                problems.push(format!(
                    "{who} is certified by {n} of the {REQUIRED_CERTIFICATIONS} master keys needed"
                ));
                continue;
            }
            let mut keys = vc
                .keys()
                .key_handles(issuers.iter())
                .for_signing()
                .alive()
                .revoked(false);
            let Some(key) = keys.next() else {
                problems.push(format!("{who} has no valid signing key that made it"));
                continue;
            };
            match sig.verify_hash(key.key(), hash.clone()) {
                Ok(()) => return Ok(fpr),
                Err(e) => problems.push(format!("bad signature by {who}: {e}")),
            }
        }
        bail!("{}", problems.join("; "))
    }
}

/// `cert` under the policy at `now`, if it is alive and not revoked.
fn usable(cert: &Cert, now: SystemTime) -> Option<ValidCert<'_>> {
    let vc = cert.with_policy(&POLICY, now).ok()?;
    if vc.alive().is_err() || matches!(vc.revocation_status(), RevocationStatus::Revoked(_)) {
        return None;
    }
    Some(vc)
}

/// The largest number of `masters` that certify one of `cert`'s user IDs.
/// Only valid, unrevoked user IDs of a usable certificate count.
fn count_certifications(cert: &Cert, masters: &[ValidCert], now: SystemTime) -> usize {
    let Some(vc) = usable(cert, now) else {
        return 0;
    };
    vc.userids()
        .filter(|ua| !matches!(ua.revocation_status(), RevocationStatus::Revoked(_)))
        .map(|ua| {
            masters
                .iter()
                .filter(|m| certified_by(ua.amalgamation(), m.primary_key().key(), now))
                .count()
        })
        .max()
        .unwrap_or(0)
}

/// Whether `issuer` has a valid certification of the user ID that it
/// hasn't revoked since. A hard revocation revokes regardless of time.
fn certified_by<'a>(
    ua: &UserIDAmalgamation<'a>,
    issuer: &'a sequoia_openpgp::packet::Key<
        sequoia_openpgp::packet::key::PublicParts,
        sequoia_openpgp::packet::key::PrimaryRole,
    >,
    now: SystemTime,
) -> bool {
    let issuer = issuer.role_as_unspecified();
    let Some(certified) = ua
        .active_certifications_by_key(&POLICY, now, issuer)
        .filter_map(|s| s.signature_creation_time())
        .max()
    else {
        return false;
    };
    !ua.valid_third_party_revocations_by_key(&POLICY, now, issuer)
        .any(|rev| {
            let hard = rev
                .reason_for_revocation()
                .is_none_or(|(reason, _)| reason.revocation_type() == RevocationType::Hard);
            hard || rev
                .signature_creation_time()
                .is_some_and(|t| t >= certified)
        })
}

fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    let fpr: Fingerprint = s
        .parse()
        .with_context(|| format!("invalid fingerprint {s:?}"))?;
    if matches!(fpr, Fingerprint::Unknown { .. }) {
        bail!("invalid fingerprint {s:?}");
    }
    Ok(fpr)
}

/// Parse `archlinux-trusted`: `FINGERPRINT:4:` lines (GnuPG owner trust
/// export format; 4 is marginal trust). Other trust levels are rejected
/// rather than given a meaning.
fn parse_trusted(r: impl BufRead) -> Result<HashSet<Fingerprint>> {
    let mut set = HashSet::new();
    for line in r.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(fpr), Some(level), Some(""), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            bail!("invalid line {line:?}");
        };
        if level != MASTER_TRUST_LEVEL {
            bail!("unsupported trust level {level:?} for {fpr}");
        }
        set.insert(parse_fingerprint(fpr)?);
    }
    Ok(set)
}

/// Parse `archlinux-revoked`: one fingerprint per line.
fn parse_revoked(r: impl BufRead) -> Result<HashSet<Fingerprint>> {
    let mut set = HashSet::new();
    for line in r.lines() {
        let line = line?;
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            set.insert(parse_fingerprint(line)?);
        }
    }
    Ok(set)
}

/// ` (user ID)` of the certificate's primary user ID, or nothing.
fn describe(cert: &Cert) -> String {
    cert.with_policy(&POLICY, None)
        .ok()
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| {
            format!(
                " ({})",
                String::from_utf8_lossy(ua.userid().value()).escape_debug()
            )
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sequoia_openpgp::packet::UserID;
    use sequoia_openpgp::packet::signature::SignatureBuilder;
    use sequoia_openpgp::serialize::MarshalInto;
    use sequoia_openpgp::types::ReasonForRevocation;

    use super::*;

    const DATA: &[u8] = b"package contents";

    fn created() -> SystemTime {
        SystemTime::now() - Duration::from_secs(100)
    }

    fn new_cert(name: &str, t: SystemTime) -> Cert {
        CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_creation_time(t)
            .add_userid(format!("{name} <{name}@example.org>"))
            .add_signing_subkey()
            .generate()
            .unwrap()
            .0
    }

    fn primary_signer(cert: &Cert) -> sequoia_openpgp::crypto::KeyPair {
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap()
    }

    fn userid(cert: &Cert) -> UserID {
        cert.userids().next().unwrap().userid().clone()
    }

    fn certify_as(typ: SignatureType, master: &Cert, cert: Cert) -> Cert {
        // Certifications before revocations, both before loading.
        let mut builder = SignatureBuilder::new(typ);
        if typ == SignatureType::CertificationRevocation {
            builder = builder
                .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")
                .unwrap();
        } else {
            builder = builder
                .set_signature_creation_time(created() + Duration::from_secs(50))
                .unwrap();
        }
        let sig = builder
            .sign_userid_binding(
                &mut primary_signer(master),
                cert.primary_key().key(),
                &userid(&cert),
            )
            .unwrap();
        cert.insert_packets(sig).unwrap().0
    }

    fn certify(master: &Cert, cert: Cert) -> Cert {
        certify_as(SignatureType::GenericCertification, master, cert)
    }

    fn sign_at(cert: &Cert, data: &[u8], t: SystemTime) -> Vec<u8> {
        let key = cert
            .keys()
            .subkeys()
            .with_policy(&POLICY, t)
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

    fn sign(cert: &Cert, data: &[u8]) -> Vec<u8> {
        sign_at(cert, data, SystemTime::now())
    }

    fn keyring(certs: &[&Cert], masters: &[&Cert], revoked: &[&Cert]) -> Result<Keyring> {
        let mut gpg = Vec::new();
        for cert in certs {
            gpg.extend(cert.to_vec().unwrap());
        }
        let list = |certs: &[&Cert], suffix: &str| -> String {
            certs
                .iter()
                .map(|c| format!("{}{suffix}\n", c.fingerprint().to_hex()))
                .collect()
        };
        Keyring::load(
            &gpg[..],
            list(masters, ":4:").as_bytes(),
            list(revoked, "").as_bytes(),
        )
    }

    struct Setup {
        masters: Vec<Cert>,
        packager: Cert,
    }

    /// Four master keys; the first `n` certify the packager key.
    fn setup(n: usize) -> Setup {
        let t = created();
        let masters: Vec<Cert> = (0..4).map(|i| new_cert(&format!("master{i}"), t)).collect();
        let mut packager = new_cert("packager", t);
        for m in &masters[..n] {
            packager = certify(m, packager);
        }
        Setup { masters, packager }
    }

    impl Setup {
        fn keyring(&self, revoked: &[&Cert]) -> Keyring {
            let mut certs: Vec<&Cert> = self.masters.iter().collect();
            certs.push(&self.packager);
            let masters: Vec<&Cert> = self.masters.iter().collect();
            keyring(&certs, &masters, revoked).unwrap()
        }
    }

    fn err(r: Result<Fingerprint>) -> String {
        format!("{:#}", r.unwrap_err())
    }

    #[test]
    fn accepts_packager_with_three_certifications() {
        let s = setup(3);
        let k = s.keyring(&[]);
        let fpr = k.verify(&sign(&s.packager, DATA), DATA).unwrap();
        assert_eq!(fpr, s.packager.fingerprint());
    }

    #[test]
    fn rejects_packager_with_two_certifications() {
        let s = setup(2);
        let e = err(s.keyring(&[]).verify(&sign(&s.packager, DATA), DATA));
        assert!(e.contains("certified by 2 of the 3"), "{e}");
    }

    #[test]
    fn rejects_modified_data() {
        let s = setup(3);
        let e = err(s
            .keyring(&[])
            .verify(&sign(&s.packager, DATA), &b"other"[..]));
        assert!(e.contains("bad signature"), "{e}");
    }

    #[test]
    fn rejects_unknown_key() {
        let s = setup(3);
        let other = new_cert("other", created());
        let e = err(s.keyring(&[]).verify(&sign(&other, DATA), DATA));
        assert!(e.contains("not in the keyring"), "{e}");
    }

    #[test]
    fn rejects_master_key_signature() {
        let s = setup(3);
        let e = err(s.keyring(&[]).verify(&sign(&s.masters[0], DATA), DATA));
        assert!(e.contains("certified by 0 of the 3"), "{e}");
    }

    #[test]
    fn rejects_revoked_packager() {
        let s = setup(3);
        let e = err(s
            .keyring(&[&s.packager])
            .verify(&sign(&s.packager, DATA), DATA));
        assert!(e.contains("not in the keyring"), "{e}");
    }

    #[test]
    fn revoked_master_does_not_count() {
        let s = setup(3);
        let k = s.keyring(&[&s.masters[0]]);
        let e = err(k.verify(&sign(&s.packager, DATA), DATA));
        assert!(e.contains("certified by 2 of the 3"), "{e}");
    }

    #[test]
    fn revoked_certification_does_not_count() {
        let mut s = setup(3);
        s.packager = certify_as(
            SignatureType::CertificationRevocation,
            &s.masters[0],
            s.packager,
        );
        let e = err(s.keyring(&[]).verify(&sign(&s.packager, DATA), DATA));
        assert!(e.contains("certified by 2 of the 3"), "{e}");
    }

    #[test]
    fn accepts_any_good_signature() {
        let s = setup(3);
        let other = new_cert("other", created());
        let mut sig = sign(&other, DATA);
        sig.extend(sign(&s.packager, DATA));
        let fpr = s.keyring(&[]).verify(&sig, DATA).unwrap();
        assert_eq!(fpr, s.packager.fingerprint());
    }

    /// The Arch keyring keeps only the latest self-signatures, which can
    /// be newer than the package signature.
    #[test]
    fn accepts_self_signatures_newer_than_signature() {
        let t = created();
        let mut s = setup(0);
        let packager = new_cert("packager", t);
        let sig = sign_at(&packager, DATA, t + Duration::from_secs(10));
        // New self-signatures now, then drop the original ones.
        let new = packager
            .set_expiration_time(&POLICY, None, &mut primary_signer(&packager), None)
            .unwrap();
        let packager = packager.insert_packets(new).unwrap().0;
        let packets = packager.into_packets().filter(|p| {
            !matches!(p, Packet::Signature(s)
                if s.signature_creation_time() < Some(t + Duration::from_secs(5))
                    && matches!(s.typ(), SignatureType::DirectKey | SignatureType::PositiveCertification))
        });
        s.packager = Cert::from_packets(packets).unwrap();
        for m in &s.masters[..3] {
            s.packager = certify(m, s.packager);
        }
        assert!(
            s.packager
                .with_policy(&POLICY, t + Duration::from_secs(10))
                .is_err()
        );
        s.keyring(&[]).verify(&sig, DATA).unwrap();
    }

    #[test]
    fn rejects_too_few_master_keys() {
        let s = setup(3);
        let e = keyring(
            &[&s.masters[0], &s.masters[1]],
            &[&s.masters[0], &s.masters[1]],
            &[],
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("2 usable master keys"), "{e}");
    }

    #[test]
    fn rejects_unknown_trust_level() {
        let e = parse_trusted(&b"2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E:5:\n"[..]).unwrap_err();
        assert!(e.to_string().contains("unsupported trust level"), "{e}");
        assert!(parse_trusted(&b"2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E\n"[..]).is_err());
        assert!(parse_trusted(&b"nothex:4:\n"[..]).is_err());
    }

    #[test]
    fn rejects_garbage_signature() {
        let s = setup(3);
        assert!(s.keyring(&[]).verify(b"not a signature", DATA).is_err());
        assert!(s.keyring(&[]).verify(b"", DATA).is_err());
    }
}
