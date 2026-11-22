//! Downloads only, for benchmarks (planning/BENCHMARKS.md): the files of a
//! list from the mirrors given, through `download_all` as skl does it, but
//! into sinks that only count. Prints the time taken and what each mirror
//! served.
//!
//! ```sh
//! scripts/netsim.sh files SIZES tmp/netsim/files
//! cargo build --release --example download
//! scripts/netsim.sh --mirror rtt=5 --mirror rtt=20 -- \
//!     sh -c 'target/release/examples/download tmp/netsim/files/list $NETSIM_MIRRORS'
//! ```

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use clap::Parser;

use skladiste::download::{Request, Sink, download_all};
use skladiste::http::{RootCerts, Url};
use skladiste::jobs::default_jobs;
use skladiste::worker::{self, Workers};

#[derive(Parser)]
struct Args {
    /// Origins at once, as skl's `-j` (default: the number of CPUs).
    #[arg(short, long)]
    jobs: Option<NonZeroUsize>,
    /// Root certificates, as skl's `--ca-certs`.
    #[arg(long, env = "SKL_CA_CERTS", value_name = "FILE")]
    ca_certs: Option<PathBuf>,
    /// Write a line for each file when it is done: seconds since the
    /// start, size, origin and path.
    #[arg(long, value_name = "FILE")]
    trace: Option<PathBuf>,
    /// Lines of "SIZE PATH", such as `netsim.sh files` writes. Downloaded
    /// largest first, as skl orders packages.
    list: PathBuf,
    /// Base URLs of the mirrors, in order of preference; each has every
    /// file at its path under the base.
    #[arg(required = true)]
    mirrors: Vec<String>,
}

/// Counts the bytes of a body and drops them.
struct Count(u64);

impl Sink for Count {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.0 += data.len() as u64;
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        self.0 = 0;
        Ok(())
    }
}

/// A finished file: when, which one, and from where.
struct Done {
    at: Duration,
    index: usize,
    origin: String,
}

fn run(args: Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.list)
        .with_context(|| format!("reading {}", args.list.display()))?;
    let mut files = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (size, path) = line
            .split_once(' ')
            .with_context(|| format!("not SIZE PATH: {line:?}"))?;
        let size: u64 = size
            .parse()
            .with_context(|| format!("bad size in {line:?}"))?;
        files.push((size, path.trim().to_owned()));
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.0));

    let mut workers = Workers::new("/proc/self/exe");
    if let Some(path) = &args.ca_certs {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        workers.set_root_certs(RootCerts::from_pem(&pem)?);
    }
    let mut requests = Vec::new();
    for (size, path) in &files {
        let urls = args
            .mirrors
            .iter()
            .map(|base| Url::parse(&format!("{}/{path}", base.trim_end_matches('/'))))
            .collect::<Result<_>>()?;
        requests.push(Request {
            urls,
            max_size: *size,
            restart_if_changed: true,
            unless: None,
            sink: Count(0),
        });
    }

    let jobs = args.jobs.unwrap_or_else(default_jobs);
    let done = Mutex::new(Vec::new());
    let start = Instant::now();
    download_all(
        &workers,
        requests,
        jobs,
        &AtomicBool::new(false),
        |index, sink, downloaded| {
            let at = start.elapsed();
            ensure!(
                sink.0 == files[index].0,
                "{} has {} bytes, not {}",
                downloaded.url,
                sink.0,
                files[index].0
            );
            let origin = downloaded.url.origin.to_string();
            done.lock().unwrap().push(Done { at, index, origin });
            Ok(())
        },
    )?;
    let elapsed = start.elapsed();
    let mut done = done.into_inner().unwrap();
    done.sort_by_key(|d| d.at);

    let total: u64 = files.iter().map(|f| f.0).sum();
    println!(
        "{} files, {:.1} MiB in {:.2} s ({:.1} Mbit/s), -j{jobs}",
        files.len(),
        total as f64 / (1 << 20) as f64,
        elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e6 / elapsed.as_secs_f64()
    );
    let mut origins: BTreeMap<&str, (usize, u64, Duration)> = BTreeMap::new();
    for d in &done {
        let o = origins.entry(&d.origin).or_default();
        o.0 += 1;
        o.1 += files[d.index].0;
        o.2 = d.at;
    }
    for (origin, (n, bytes, last)) in &origins {
        println!(
            "  {origin}: {n} files, {:.1} MiB, last done at {:.2} s",
            *bytes as f64 / (1 << 20) as f64,
            last.as_secs_f64()
        );
    }
    if let Some(path) = &args.trace {
        let mut out = BufWriter::new(
            File::create(path).with_context(|| format!("creating {}", path.display()))?,
        );
        for d in &done {
            let (size, file) = &files[d.index];
            writeln!(out, "{:.4} {size} {} {file}", d.at.as_secs_f64(), d.origin)?;
        }
        out.flush()?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == worker::SUBCOMMAND) {
        return worker::main(args);
    }
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}
