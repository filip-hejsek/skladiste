//! Syncing repo databases from a local HTTP server and reading them in the
//! sandboxed worker.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use skladiste::arch::repo::{self, Config};
use skladiste::store::Store;
use skladiste::worker::Workers;

fn workers() -> Workers {
    Workers::new(env!("CARGO_BIN_EXE_skl"))
}

/// A gzip-compressed database with a `desc` for each `(name, version)`.
fn make_db(packages: &[(&str, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut b = tar::Builder::new(gz);
    for (name, version) in packages {
        let desc = format!(
            "%FILENAME%\n{name}-{version}-x86_64.pkg.tar.zst\n\n%NAME%\n{name}\n\n\
             %VERSION%\n{version}\n\n%CSIZE%\n100\n\n%SHA256SUM%\n{}\n\n\
             %ARCH%\nx86_64\n\n%DEPENDS%\nglibc>=2.40\n\n",
            "ab".repeat(32)
        );
        let mut h = tar::Header::new_ustar();
        h.set_mode(0o644);
        h.set_size(desc.len() as u64);
        b.append_data(&mut h, format!("{name}-{version}/desc"), desc.as_bytes())
            .unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

/// Serve `files` (path, content) over HTTP on a local port; returns the
/// base URL.
fn serve(files: Vec<(&'static str, Vec<u8>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut conn = conn.unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let path = request_line.split(' ').nth(1).unwrap();
            let response = match files.iter().find(|(p, _)| *p == path) {
                Some((_, content)) => {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: yesterday\r\n\r\n",
                        content.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(content);
                    r
                }
                None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            let _ = conn.write_all(&response);
        }
    });
    format!("http://{addr}")
}

#[test]
fn sync_and_read() {
    let db = make_db(&[("glibc", "2.44-1"), ("bash", "1:5.3.3-2")]);
    let base = serve(vec![
        ("/main/x86_64/main.db", db.clone()),
        ("/bad/x86_64/bad.db", b"not a database".to_vec()),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let workers = workers();

    let config = Config::new(&format!("{base}/$repo/$arch"), "main").unwrap();
    let record = repo::fetch_db(&workers, &store, &config).unwrap();
    assert_eq!(record.size, db.len() as u64);
    assert_eq!(record.url, format!("{base}/main/x86_64/main.db"));
    assert_eq!(record.last_modified.as_deref(), Some("yesterday"));
    let entries = repo::load_db(&workers, &store, &record).unwrap();
    let names: Vec<_> = entries
        .iter()
        .map(|e| (&*e.name, &*e.version, &*e.depends[0]))
        .collect();
    assert_eq!(
        names,
        [
            ("glibc", "2.44-1", "glibc>=2.40"),
            ("bash", "1:5.3.3-2", "glibc>=2.40")
        ]
    );

    let config = Config::new(&format!("{base}/$repo/$arch"), "bad").unwrap();
    let record = repo::fetch_db(&workers, &store, &config).unwrap();
    let err = format!(
        "{:#}",
        repo::load_db(&workers, &store, &record).unwrap_err()
    );
    assert!(err.contains("unsupported compression"), "{err}");

    let config = Config::new(&format!("{base}/$repo/$arch"), "missing").unwrap();
    let err = format!(
        "{:#}",
        repo::fetch_db(&workers, &store, &config).unwrap_err()
    );
    assert!(err.contains("404"), "{err}");
}
