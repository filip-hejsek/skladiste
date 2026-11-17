//! Helpers shared by the commands of the CLI. Commands of a frontend are
//! in submodules (e.g. [`arch`]).

use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, sync_channel};

use anyhow::Result;

use skladiste::download::{self, Downloaded, Request, Sink};
use skladiste::jobs::{both, par_map_iter};
use skladiste::worker::Workers;

pub(crate) mod arch;

/// Downloads that wait for a job, at most; the download stage waits when
/// there are more. Each can keep a file open.
const MAX_WAITING: usize = 64;

/// Download `requests`, and meanwhile run `job` on up to `jobs` threads:
/// on what `downloaded` makes of each finished download (if anything),
/// and on the items in `ready`, in their order. Returns the results of
/// `job` in no particular order.
///
/// Downloads go one after another per server, in the order of `requests`
/// (see [`download::download_all`]). `downloaded` is called with the index
/// of the request, on the thread that downloads from its server, so the
/// next download from there waits for it. Finished downloads are taken
/// before items of `ready`, so that the download stage isn't held up.
///
/// Once something fails, no new downloads or jobs start; those under way
/// finish.
pub(crate) fn fetch_and_run<S: Sink, T: Send, R: Send>(
    workers: &Workers,
    jobs: NonZeroUsize,
    ready: Vec<T>,
    requests: Vec<Request<S>>,
    downloaded: impl Fn(usize, S, Downloaded) -> Result<Option<T>> + Sync,
    job: impl Fn(T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let failed = &AtomicBool::new(false);
    let downloaded = &downloaded;
    let (tx, rx) = sync_channel(MAX_WAITING);
    let feed = Feed {
        downloads: rx,
        ready: ready.into_iter(),
    };
    let (downloads, results) = std::thread::scope(|s| {
        // Owns the sender, so the jobs end when the downloads have.
        let stage = s.spawn(move || {
            download::download_all(workers, requests, jobs, failed, |i, sink, download| {
                if let Some(item) = downloaded(i, sink, download)? {
                    // Fails only once the jobs have stopped for a failure.
                    let _ = tx.send(item);
                }
                Ok(())
            })
        });
        let results = par_map_iter(feed, jobs, failed, job);
        let downloads = stage
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p));
        (downloads, results)
    });
    Ok(both(downloads, results)?.1)
}

/// What the jobs of [`fetch_and_run`] work on.
struct Feed<T> {
    downloads: Receiver<T>,
    ready: std::vec::IntoIter<T>,
}

impl<T> Iterator for Feed<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if let Ok(item) = self.downloads.try_recv() {
            return Some(item);
        }
        self.ready.next().or_else(|| self.downloads.recv().ok())
    }
}

pub(crate) fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use anyhow::ensure;

    use super::*;

    #[test]
    fn downloads_come_before_ready_items() {
        let (tx, rx) = sync_channel(4);
        let mut feed = Feed {
            downloads: rx,
            ready: vec![1, 2].into_iter(),
        };
        tx.send(10).unwrap();
        assert_eq!(feed.next(), Some(10));
        assert_eq!(feed.next(), Some(1));
        tx.send(11).unwrap();
        assert_eq!(feed.next(), Some(11));
        assert_eq!(feed.next(), Some(2));
        // Nothing is ready: waits for the downloads, until they end.
        tx.send(12).unwrap();
        drop(tx);
        assert_eq!(feed.next(), Some(12));
        assert_eq!(feed.next(), None);
    }

    #[test]
    fn jobs_without_downloads() {
        // No worker is started without requests.
        let workers = Workers::new("/nonexistent");
        let jobs = NonZeroUsize::new(3).unwrap();
        let run = |fail: Option<u32>| {
            let requests: Vec<Request<Vec<u8>>> = Vec::new();
            fetch_and_run(
                &workers,
                jobs,
                (0..20).collect(),
                requests,
                |_, _, _| Ok(None),
                |n: u32| {
                    ensure!(Some(n) != fail, "job {n} failed");
                    Ok(n * 2)
                },
            )
        };
        let mut results = run(None).unwrap();
        results.sort();
        assert_eq!(results, (0..20).map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(run(Some(7)).unwrap_err().to_string(), "job 7 failed");
    }
}
