//! Arch version comparison, as pacman's `vercmp` (`alpm_pkg_vercmp`).

use std::cmp::Ordering;

/// Compare two versions `[EPOCH:]VERSION[-RELEASE]`. Epochs (default 0)
/// are compared first, then versions; releases only if both have one, so
/// `1.0` equals `1.0-2`.
pub fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (ea, va, ra) = split(a);
    let (eb, vb, rb) = split(b);
    rpmvercmp(ea, eb)
        .then_with(|| rpmvercmp(va, vb))
        .then_with(|| match (ra, rb) {
            (Some(ra), Some(rb)) => rpmvercmp(ra, rb),
            _ => Ordering::Equal,
        })
}

/// Split into epoch, version and release, as alpm's `parseEVR`.
fn split(evr: &str) -> (&str, &str, Option<&str>) {
    let digits = evr.bytes().take_while(u8::is_ascii_digit).count();
    let (epoch, rest) = match evr[digits..].strip_prefix(':') {
        Some(rest) if digits > 0 => (&evr[..digits], rest),
        Some(rest) => ("0", rest),
        None => ("0", evr),
    };
    match rest.rsplit_once('-') {
        Some((version, release)) => (epoch, version, Some(release)),
        None => (epoch, rest, None),
    }
}

/// rpm's version segment comparison, as alpm implements it: runs of
/// digits compare numerically and are newer than runs of letters; more
/// separators at the same place is newer. When one version runs out,
/// the other is older if what remains of it starts with a letter and
/// newer otherwise (`1.5a` < `1.5` < `1.5.a`).
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let (start_i, start_j) = (i, j);
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i == a.len() || j == b.len() {
            break;
        }
        if i - start_i != j - start_j {
            return (i - start_i).cmp(&(j - start_j));
        }
        let numeric = a[i].is_ascii_digit();
        let class = |c: &u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        let seg_a = &a[i..i + a[i..].iter().take_while(|c| class(c)).count()];
        let seg_b = &b[j..j + b[j..].iter().take_while(|c| class(c)).count()];
        i += seg_a.len();
        j += seg_b.len();
        if seg_b.is_empty() {
            // Different kinds of segment: numbers are newer.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let ord = if numeric {
            let trim = |s: &[u8]| -> usize { s.iter().take_while(|&&c| c == b'0').count() };
            let (na, nb) = (&seg_a[trim(seg_a)..], &seg_b[trim(seg_b)..]);
            na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
        } else {
            seg_a.cmp(seg_b)
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    let (rest_a, rest_b) = (&a[i..], &b[j..]);
    if rest_a.is_empty() && rest_b.is_empty() {
        return Ordering::Equal;
    }
    let alpha = |s: &[u8]| s.first().is_some_and(u8::is_ascii_alphabetic);
    if (rest_a.is_empty() && !alpha(rest_b)) || alpha(rest_a) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All cases of pacman's `test/util/vercmptest.sh` (as of pacman
    /// commit a6f7467), and some more.
    #[test]
    fn pacman_cases() {
        use Ordering::*;
        let cases = [
            // All similar length, no pkgrel.
            ("1.5.0", "1.5.0", Equal),
            ("1.5.1", "1.5.0", Greater),
            // Mixed length.
            ("1.5.1", "1.5", Greater),
            // With pkgrel, simple.
            ("1.5.0-1", "1.5.0-1", Equal),
            ("1.5.0-1", "1.5.0-2", Less),
            ("1.5.0-1", "1.5.1-1", Less),
            ("1.5.0-2", "1.5.1-1", Less),
            // With pkgrel, mixed lengths.
            ("1.5-1", "1.5.1-1", Less),
            ("1.5-2", "1.5.1-1", Less),
            ("1.5-2", "1.5.1-2", Less),
            // Mixed pkgrel inclusion.
            ("1.5", "1.5-1", Equal),
            ("1.5-1", "1.5", Equal),
            ("1.1-1", "1.1", Equal),
            ("1.0-1", "1.1", Less),
            ("1.1-1", "1.0", Greater),
            // Alphanumeric versions.
            ("1.5b-1", "1.5-1", Less),
            ("1.5b", "1.5", Less),
            ("1.5b-1", "1.5", Less),
            ("1.5b", "1.5.1", Less),
            // From the manpage.
            ("1.0a", "1.0alpha", Less),
            ("1.0alpha", "1.0b", Less),
            ("1.0b", "1.0beta", Less),
            ("1.0beta", "1.0rc", Less),
            ("1.0rc", "1.0", Less),
            // Going crazy? alpha-dotted versions.
            ("1.5.a", "1.5", Greater),
            ("1.5.b", "1.5.a", Greater),
            ("1.5.1", "1.5.b", Greater),
            // Alpha dots and dashes.
            ("1.5.b-1", "1.5.b", Equal),
            ("1.5-1", "1.5.b", Less),
            // Same/similar content, differing separators.
            ("2.0", "2_0", Equal),
            ("2.0_a", "2_0.a", Equal),
            ("2.0a", "2.0.a", Less),
            ("2___a", "2_a", Greater),
            // Epoch included version comparisons.
            ("0:1.0", "0:1.0", Equal),
            ("0:1.0", "0:1.1", Less),
            ("1:1.0", "0:1.0", Greater),
            ("1:1.0", "0:1.1", Greater),
            ("1:1.0", "2:1.1", Less),
            // Epoch + sometimes present pkgrel.
            ("1:1.0", "0:1.0-1", Greater),
            ("1:1.0-1", "0:1.1-1", Greater),
            // Epoch included on one version.
            ("0:1.0", "1.0", Equal),
            ("0:1.0", "1.1", Less),
            ("0:1.1", "1.0", Greater),
            ("1:1.0", "1.0", Greater),
            ("1:1.0", "1.1", Greater),
            ("1:1.1", "1.1", Greater),
            // Not in pacman's tests; results from its `alpm_pkg_vercmp`.
            ("1.0", "1.0.a", Less),
            ("1.5b", "1.5a", Greater),
            ("1.0beta", "1.0pre", Less),
            ("1.0pre", "1.0rc", Less),
            ("1.1", "1.0.1", Greater),
            ("1.01", "1.1", Equal),
            ("1.10", "1.9", Greater),
            ("1.0010", "1.9", Greater),
            ("1.0", "1..0", Less),
            ("1.0", "1+0", Equal),
            ("1.0.0", "1.0..0", Less),
            ("1.5.0-1", "1.5", Greater),
            ("1.1-1", "1.1.1", Less),
            ("1.1-2", "1.1.1", Less),
            ("2:1.0", "1:1.1", Greater),
            ("1:1.0-1", "1:1.0", Equal),
            ("1:1.0-1", "1:1.0-2", Less),
            (":1.0", "0:1.0", Equal),
            ("1.0-", "1.0", Equal),
            ("1.0-a-1", "1.0-a-2", Less),
            ("1a", "1.a", Less),
            ("1.5.", "1.5", Greater),
        ];
        for (a, b, expected) in cases {
            assert_eq!(vercmp(a, b), expected, "vercmp {a} {b}");
            assert_eq!(vercmp(b, a), expected.reverse(), "vercmp {b} {a}");
        }
    }
}
