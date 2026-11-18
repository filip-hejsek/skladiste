//! Objects: skl's own records in the store (package manifests, build
//! specs), as opposed to blobs, which are file contents.
//!
//! An object is a header followed by a body. The header lists everything
//! the object refers to, one per line, after a first line with the
//! format, the hash algorithm and the count:
//!
//! ```text
//! skl-object 1 blake3 2
//! b 4f2a…
//! o e7d3…
//! ```
//!
//! `b` is a blob, `o` an object, so following references needs no
//! knowledge of the body. The body is canonical JSON (see [`encode`]) and
//! refers to blobs and objects only by their index in the header, as a
//! JSON object with the single key `#` (`{"#":0}`), so that the core finds
//! references in any body, also in parts whose schema only a frontend
//! knows. The header is canonical too: each reference once, in the order
//! of its first use in the body. So equal content always gives equal
//! bytes, and an object's address ([`address`]) is the hash of its bytes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, Read as _};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::Hash;

/// The first word of an object's header.
const MAGIC: &str = "skl-object";

/// The version of the object format.
const FORMAT: u32 = 1;

/// The hash algorithm of the references in the header.
const ALGORITHM: &str = "blake3";

/// The key of a reference in a body.
pub const REF_KEY: &str = "#";

/// Largest number of references an object may have.
const MAX_REFS: usize = 1 << 24;

/// What an object refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ref {
    Blob(Hash),
    Object(Hash),
}

impl Ref {
    fn tag(self) -> char {
        match self {
            Ref::Blob(_) => 'b',
            Ref::Object(_) => 'o',
        }
    }

    fn hash(self) -> Hash {
        match self {
            Ref::Blob(h) | Ref::Object(h) => h,
        }
    }
}

/// A reference in a body, `{"#":N}`: the index of a [`Ref`] in a list of
/// them (the header, once the object is written).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    #[serde(rename = "#")]
    pub index: u64,
}

/// Collects the references of a body being built: [`Refs::add`] gives the
/// [`Index`] to put in the body.
#[derive(Debug, Default, Clone)]
pub struct Refs {
    refs: Vec<Ref>,
    known: HashMap<Ref, u64>,
}

impl Refs {
    pub fn new() -> Refs {
        Refs::default()
    }

    /// The index of `r`, added if it's new.
    pub fn add(&mut self, r: Ref) -> Index {
        let next = self.refs.len() as u64;
        let index = *self.known.entry(r).or_insert(next);
        if index == next {
            self.refs.push(r);
        }
        Index { index }
    }

    pub fn as_slice(&self) -> &[Ref] {
        &self.refs
    }
}

/// An object read from the store.
#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    /// The header's references.
    pub refs: Vec<Ref>,
    /// The body. Every reference in it is within `refs`.
    pub body: Value,
}

impl Object {
    /// What `index` (from the body) refers to.
    pub fn get(&self, index: Index) -> Result<Ref> {
        usize::try_from(index.index)
            .ok()
            .and_then(|i| self.refs.get(i))
            .copied()
            .with_context(|| format!("no reference {}", index.index))
    }

    /// The blob `index` refers to; an error if it's an object.
    pub fn blob(&self, index: Index) -> Result<Hash> {
        match self.get(index)? {
            Ref::Blob(h) => Ok(h),
            Ref::Object(_) => bail!("reference {} is an object, not a blob", index.index),
        }
    }

    /// The object `index` refers to; an error if it's a blob.
    pub fn object(&self, index: Index) -> Result<Hash> {
        match self.get(index)? {
            Ref::Object(h) => Ok(h),
            Ref::Blob(_) => bail!("reference {} is a blob, not an object", index.index),
        }
    }
}

/// The address of the object whose bytes are `data`: their BLAKE3 hash in
/// key derivation mode, so that no file, whose blob is addressed by its
/// plain hash, has the address of an object.
pub fn address(data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key("skl object");
    hasher.update(data);
    hasher.finalize().into()
}

/// The bytes of the object with `body`, whose references are indexes into
/// `refs`: the header lists the references used, each once, in the order
/// of their first use in the body (unused ones are left out), and the body
/// is renumbered to match and written as canonical JSON:
///
/// - no whitespace outside strings;
/// - object keys sorted by their UTF-8 bytes;
/// - strings escape only `"`, `\` and control characters (`\b`, `\f`,
///   `\n`, `\r`, `\t`, otherwise `\u00XX` in lowercase hex);
/// - numbers are integers; floats are an error.
///
/// This is `serde_json`'s compact output of a [`Value`], whose maps are
/// sorted. An object in the body with the key `#` must be a reference:
/// that key alone, with an index into `refs`.
pub fn encode(refs: &[Ref], body: &Value) -> Result<Vec<u8>> {
    let mut enc = Encoder {
        refs,
        renumbered: HashMap::new(),
        header: Vec::new(),
        out: Vec::new(),
    };
    enc.value(body)?;
    let mut data = format!("{MAGIC} {FORMAT} {ALGORITHM} {}\n", enc.header.len());
    for r in &enc.header {
        writeln!(data, "{} {}", r.tag(), r.hash()).unwrap();
    }
    let mut data = data.into_bytes();
    data.extend_from_slice(&enc.out);
    Ok(data)
}

struct Encoder<'a> {
    refs: &'a [Ref],
    /// Each reference used so far, by its index in the header.
    renumbered: HashMap<Ref, u64>,
    header: Vec<Ref>,
    out: Vec<u8>,
}

impl Encoder<'_> {
    fn value(&mut self, v: &Value) -> Result<()> {
        match v {
            Value::Null => self.out.extend_from_slice(b"null"),
            Value::Bool(b) => self
                .out
                .extend_from_slice(if *b { b"true" } else { b"false" }),
            Value::Number(n) => {
                ensure!(n.is_i64() || n.is_u64(), "not an integer: {n}");
                write!(Bytes(&mut self.out), "{n}").unwrap();
            }
            Value::String(s) => serde_json::to_writer(&mut self.out, s)?,
            Value::Array(a) => {
                self.out.push(b'[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.value(v)?;
                }
                self.out.push(b']');
            }
            Value::Object(m) => {
                if let Some(index) = ref_index(m)? {
                    let r = usize::try_from(index)
                        .ok()
                        .and_then(|i| self.refs.get(i))
                        .with_context(|| format!("no reference {index}"))?;
                    let next = self.header.len() as u64;
                    let n = *self.renumbered.entry(*r).or_insert(next);
                    if n == next {
                        self.header.push(*r);
                    }
                    write!(Bytes(&mut self.out), "{{\"{REF_KEY}\":{n}}}").unwrap();
                    return Ok(());
                }
                // `serde_json::Map` is a `BTreeMap`: keys come sorted.
                self.out.push(b'{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    serde_json::to_writer(&mut self.out, k)?;
                    self.out.push(b':');
                    self.value(v)?;
                }
                self.out.push(b'}');
            }
        }
        Ok(())
    }
}

/// `fmt::Write` for a byte vector.
struct Bytes<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Bytes<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// The index of `m` if it is a reference; an error if it has the key `#`
/// but isn't one.
fn ref_index(m: &serde_json::Map<String, Value>) -> Result<Option<u64>> {
    let Some(v) = m.get(REF_KEY) else {
        return Ok(None);
    };
    ensure!(m.len() == 1, "a reference must have no other keys");
    let index = v
        .as_u64()
        .with_context(|| format!("bad reference index {v}"))?;
    Ok(Some(index))
}

/// Parse the bytes of an object: the header, and the body, in which every
/// reference must be within the header. The address isn't checked here
/// (see [`crate::store::Store::read_object`]), nor that the form is
/// canonical: only the supervisor writes objects, always through
/// [`encode`].
pub fn decode(data: &[u8]) -> Result<Object> {
    let (refs, body) = parse_header(data)?;
    let body: Value = serde_json::from_slice(body).context("parsing the body")?;
    check_refs(&body, refs.len())?;
    Ok(Object { refs, body })
}

/// The references of an object, and the rest of its bytes (the body).
pub fn parse_header(data: &[u8]) -> Result<(Vec<Ref>, &[u8])> {
    let mut rest = data;
    let refs = read_header(&mut rest)?;
    Ok((refs, rest))
}

/// Read the header of an object from `reader`, leaving it at the start of
/// the body. Reads no more than the header, so following references (as
/// the GC does) costs no more than the header's size.
pub fn read_header(reader: &mut impl BufRead) -> Result<Vec<Ref>> {
    let first = read_line(reader)?.context("no header")?;
    let count = first
        .strip_prefix(&format!("{MAGIC} {FORMAT} {ALGORITHM} "))
        .and_then(|n| n.parse::<usize>().ok())
        .filter(|&n| n <= MAX_REFS)
        .with_context(|| format!("bad object header {first:?}"))?;
    let mut refs = Vec::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let line = read_line(reader)?.context("header ends early")?;
        let r = match line.split_once(' ') {
            Some(("b", hash)) => Ref::Blob(hash.parse()?),
            Some(("o", hash)) => Ref::Object(hash.parse()?),
            _ => bail!("bad reference {line:?}"),
        };
        refs.push(r);
    }
    Ok(refs)
}

/// Longest line in a header, newline included.
const MAX_HEADER_LINE: u64 = 128;

/// The next line of a header without its newline; `None` if there is no
/// complete line, or it isn't UTF-8 or too long.
fn read_line(reader: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = Vec::new();
    reader
        .take(MAX_HEADER_LINE)
        .read_until(b'\n', &mut line)
        .context("reading the header")?;
    if line.pop() != Some(b'\n') {
        return Ok(None);
    }
    Ok(String::from_utf8(line).ok())
}

/// Check that every reference in `v` is a valid one, below `count`.
fn check_refs(v: &Value, count: usize) -> Result<()> {
    match v {
        Value::Array(a) => a.iter().try_for_each(|v| check_refs(v, count)),
        Value::Object(m) => match ref_index(m)? {
            Some(i) => {
                ensure!(i < count as u64, "reference {i} is not in the header");
                Ok(())
            }
            None => m.values().try_for_each(|v| check_refs(v, count)),
        },
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hash(s: &str) -> Hash {
        blake3::hash(s.as_bytes()).into()
    }

    #[test]
    fn canonical_json() {
        let body = json!({
            "z": 1, "a": [true, null, -0, -5, 18446744073709551615u64],
            "é": "a/é\u{1}\n\t\"\\\u{7f}", "B": {}
        });
        let data = encode(&[], &body).unwrap();
        let text = std::str::from_utf8(&data).unwrap();
        assert_eq!(
            text,
            "skl-object 1 blake3 0\n\
             {\"B\":{},\"a\":[true,null,0,-5,18446744073709551615],\
             \"z\":1,\"é\":\"a/é\\u0001\\n\\t\\\"\\\\\u{7f}\"}"
        );
        assert!(encode(&[], &json!({"x": 1.5})).is_err());
        assert_eq!(decode(&data).unwrap().body, body);
    }

    #[test]
    fn references_in_order_of_first_use() {
        let (a, b, c) = (
            Ref::Blob(hash("a")),
            Ref::Object(hash("b")),
            Ref::Blob(hash("c")),
        );
        // `c` is unused; `a` is used twice. "k" sorts before "x".
        let refs = [c, a, b];
        let body = json!({"x": [{"#": 1}, {"#": 2}], "k": {"#": 2}, "y": {"#": 1}});
        let data = encode(&refs, &body).unwrap();
        let obj = decode(&data).unwrap();
        assert_eq!(obj.refs, [b, a]);
        assert_eq!(
            obj.body,
            json!({"k": {"#": 0}, "x": [{"#": 1}, {"#": 0}], "y": {"#": 1}})
        );
        assert_eq!(obj.blob(Index { index: 1 }).unwrap(), hash("a"));
        assert!(obj.blob(Index { index: 0 }).is_err());
        assert_eq!(obj.object(Index { index: 0 }).unwrap(), hash("b"));
        assert!(obj.get(Index { index: 2 }).is_err());
        // The same references listed otherwise, or twice, give the same
        // bytes.
        let refs = [b, a, a];
        let body = json!({"x": [{"#": 2}, {"#": 0}], "k": {"#": 0}, "y": {"#": 1}});
        assert_eq!(encode(&refs, &body).unwrap(), data);
        let header = format!("skl-object 1 blake3 2\no {}\nb {}\n", hash("b"), hash("a"));
        assert!(data.starts_with(header.as_bytes()));
    }

    #[test]
    fn bad_references() {
        let r = [Ref::Blob(hash("a"))];
        for body in [
            json!({"#": 1}),
            json!({"#": -1}),
            json!({"#": "0"}),
            json!({"#": 0, "x": 1}),
        ] {
            assert!(encode(&r, &body).is_err(), "{body}");
            let data = format!("skl-object 1 blake3 1\nb {}\n{body}", hash("a"));
            assert!(decode(data.as_bytes()).is_err(), "{body}");
        }
        for data in [
            "",
            "skl-object 1 blake3 1\n{}",
            "skl-object 2 blake3 0\n{}",
            "skl-object 1 sha256 0\n{}",
            "skl-object 1 blake3 0\n{",
            "skl-object 1 blake3 1\nx 00\n{}",
        ] {
            assert!(decode(data.as_bytes()).is_err(), "{data:?}");
        }
    }

    #[test]
    fn header_alone() {
        let r = [Ref::Blob(hash("a")), Ref::Object(hash("b"))];
        let data = encode(&r, &json!([{"#": 0}, {"#": 1}])).unwrap();
        let mut reader = &data[..];
        assert_eq!(read_header(&mut reader).unwrap(), r);
        assert_eq!(reader, br##"[{"#":0},{"#":1}]"##);
        let long = format!("skl-object 1 blake3 1\nb {}0\n", hash("a"));
        assert!(read_header(&mut long.as_bytes()).is_err());
    }

    #[test]
    fn addresses_differ_from_blobs() {
        let data = encode(&[], &json!({})).unwrap();
        assert_ne!(address(&data), Hash::from(blake3::hash(&data)));
    }

    #[test]
    fn collected_refs() {
        let mut refs = Refs::new();
        let a = refs.add(Ref::Blob(hash("a")));
        let b = refs.add(Ref::Object(hash("a")));
        assert_eq!(refs.add(Ref::Blob(hash("a"))), a);
        assert_ne!(a, b);
        assert_eq!(refs.as_slice().len(), 2);
        assert_eq!(serde_json::to_value(b).unwrap(), json!({"#": 1}));
    }
}
