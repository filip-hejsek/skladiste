//! Running independent jobs on a few threads, e.g. one import worker each.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let worker = || {
        let mut done = Vec::new();
        while !failed.load(Ordering::Relaxed) {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(i) else { break };
            let result = f(item);
            if result.is_err() {
                failed.store(true, Ordering::Relaxed);
            }
            done.push((i, result));
        }
        done
    };
    let threads = jobs.get().min(items.len());
    let done: Vec<(usize, Result<R>)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads).map(|_| s.spawn(worker)).collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });

    let mut slots: Vec<Option<Result<R>>> = items.iter().map(|_| None).collect();
    for (i, result) in done {
        slots[i] = Some(result);
    }
    let mut results = Vec::with_capacity(items.len());
    let mut error = None;
    // Items not started after a failure are `None`.
    for result in slots.into_iter().flatten() {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;
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
}
