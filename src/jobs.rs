//! Running independent jobs on a few threads, e.g. one import worker each.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

/// Number of jobs to run at once by default: the number of CPUs.
pub fn default_jobs() -> NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
}

/// Call `f` on each item, on up to `jobs` threads, and return the results
/// in the order of `items`.
///
/// Once a call fails, no new calls start; those already running finish.
/// The error of the first failed item (in the order of `items`) is
/// returned, and the errors of other failed items are printed to stderr.
pub fn par_map<T: Sync, R: Send>(
    items: &[T],
    jobs: NonZeroUsize,
    f: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    par_map_iter(items.iter(), jobs, &AtomicBool::new(false), f)
}

/// Like [`par_map`], for items that come from an iterator, which may
/// block: e.g. what an earlier stage hands over through a channel, as it
/// gets ready. The results are in the order the items came in.
///
/// `failed` is shared by the stages of one task. It is set when a call
/// fails, and once it is set, here or by another stage, no new calls
/// start. Then fewer results than items are returned, without an error
/// if no call failed here.
pub fn par_map_iter<T: Send, R: Send>(
    items: impl Iterator<Item = T> + Send,
    jobs: NonZeroUsize,
    failed: &AtomicBool,
    f: impl Fn(T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let threads = match items.size_hint() {
        (_, Some(n)) => jobs.get().min(n),
        _ => jobs.get(),
    };
    let items = Mutex::new(items.enumerate());
    let worker = || {
        let mut done = Vec::new();
        while !failed.load(Ordering::Relaxed) {
            // May block with the lock held; the other idle threads would
            // wait for the same item.
            let Some((i, item)) = items.lock().unwrap().next() else {
                break;
            };
            // Something may have failed while this thread waited.
            if failed.load(Ordering::Relaxed) {
                break;
            }
            let result = f(item);
            if result.is_err() {
                failed.store(true, Ordering::Relaxed);
            }
            done.push((i, result));
        }
        done
    };
    let mut done: Vec<(usize, Result<R>)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads).map(|_| s.spawn(worker)).collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    done.sort_by_key(|&(i, _)| i);

    let mut results = Vec::with_capacity(done.len());
    let mut error = None;
    for (_, result) in done {
        match result {
            Ok(r) => results.push(r),
            Err(e) if error.is_none() => error = Some(e),
            Err(e) => eprintln!("Error: {e:?}"),
        }
    }
    match error {
        Some(e) => Err(e),
        None => Ok(results),
    }
}

/// The results of two stages of one task that ran at once. If both
/// failed, the first one's error is returned and the second one's is
/// printed to stderr, as [`par_map`] does with its items.
pub fn both<A, B>(first: Result<A>, second: Result<B>) -> Result<(A, B)> {
    match (first, second) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
        (Err(e), Err(other)) => {
            eprintln!("Error: {other:?}");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn jobs(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn results_keep_order() {
        let items: Vec<u64> = (0..50).collect();
        let out = par_map(&items, jobs(4), |&i| {
            // Later items finish first.
            std::thread::sleep(Duration::from_millis(50 - i));
            Ok(i * 2)
        })
        .unwrap();
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn runs_at_most_jobs_at_once() {
        let running = Mutex::new((0, 0)); // (now, max)
        let items = [(); 20];
        par_map(&items, jobs(3), |_| {
            {
                let mut r = running.lock().unwrap();
                r.0 += 1;
                r.1 = r.1.max(r.0);
            }
            std::thread::sleep(Duration::from_millis(10));
            running.lock().unwrap().0 -= 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(running.into_inner().unwrap(), (0, 3));
    }

    #[test]
    fn stops_after_an_error() {
        let started = AtomicUsize::new(0);
        let items: Vec<usize> = (0..100).collect();
        let err = par_map(&items, jobs(2), |&i| {
            started.fetch_add(1, Ordering::Relaxed);
            anyhow::ensure!(i != 3, "item {i} failed");
            // Slow enough that the other thread can't start many items
            // between taking item 3 and recording its failure.
            std::thread::sleep(Duration::from_millis(20));
            Ok(i)
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "item 3 failed");
        // Each thread finishes at most the item it was working on.
        assert!(started.into_inner() <= 6);
    }

    #[test]
    fn first_error_in_item_order_is_returned() {
        let items = [0, 1];
        let err = par_map(&items, jobs(2), |&i| -> Result<()> {
            // Item 1 fails first.
            std::thread::sleep(Duration::from_millis(50 * (1 - i)));
            anyhow::bail!("item {i} failed")
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "item 0 failed");
    }

    #[test]
    fn empty() {
        let out = par_map(&[] as &[()], jobs(4), |_| Ok(())).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn items_from_a_channel() {
        let (tx, rx) = std::sync::mpsc::channel();
        let failed = AtomicBool::new(false);
        let out = std::thread::scope(|s| {
            s.spawn(move || {
                for i in 0..20u64 {
                    std::thread::sleep(Duration::from_millis(1));
                    tx.send(i).unwrap();
                }
            });
            par_map_iter(rx.into_iter(), jobs(3), &failed, |i| {
                // Later items finish first.
                std::thread::sleep(Duration::from_millis(20 - i));
                Ok(i * 2)
            })
        })
        .unwrap();
        assert_eq!(out, (0..20).map(|i| i * 2).collect::<Vec<_>>());
        assert!(!failed.into_inner());
    }

    #[test]
    fn stops_when_another_stage_failed() {
        let failed = AtomicBool::new(false);
        let out = par_map_iter(0..100, jobs(1), &failed, |i| {
            if i == 2 {
                failed.store(true, Ordering::Relaxed);
            }
            Ok(i)
        })
        .unwrap();
        assert_eq!(out, [0, 1, 2]);

        // A failure here is seen by the other stages.
        let failed = AtomicBool::new(false);
        let err = par_map_iter(0..100, jobs(1), &failed, |i| {
            anyhow::ensure!(i != 2, "item {i} failed");
            Ok(i)
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "item 2 failed");
        assert!(failed.into_inner());
    }

    #[test]
    fn both_stages() {
        let ok = |n: u32| -> Result<u32> { Ok(n) };
        let err = |msg: &str| -> Result<u32> { Err(anyhow::anyhow!("{msg}")) };
        assert_eq!(both(ok(1), ok(2)).unwrap(), (1, 2));
        assert_eq!(both(err("a"), ok(2)).unwrap_err().to_string(), "a");
        assert_eq!(both(ok(1), err("b")).unwrap_err().to_string(), "b");
        assert_eq!(both(err("a"), err("b")).unwrap_err().to_string(), "a");
    }
}
