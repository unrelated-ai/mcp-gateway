//! Concurrent upstream work with one deadline, stable result ordering, and no detached tasks.
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use std::time::Duration;
use tokio::time::{Instant, error::Elapsed};

#[derive(Clone, Copy)]
pub(super) struct AggregationPolicy {
    pub concurrency: usize,
    pub timeout: Duration,
}

impl AggregationPolicy {
    pub fn from_env() -> Self {
        let concurrency = unrelated_env::positive_u64("UNRELATED_GATEWAY_UPSTREAM_CONCURRENCY")
            .unwrap_or(8)
            .clamp(1, 64);
        let timeout_secs =
            unrelated_env::positive_u64("UNRELATED_GATEWAY_UPSTREAM_OPERATION_TIMEOUT_SECS")
                .unwrap_or(10)
                .clamp(1, 300);
        Self {
            concurrency: usize::try_from(concurrency).unwrap_or(8),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn collect<'a, T: Send + 'a>(
        self,
        futures: Vec<BoxFuture<'a, T>>,
    ) -> BoxFuture<'a, Vec<Result<T, Elapsed>>> {
        async move {
            let started = Instant::now();
            let deadline = started + self.timeout;
            let mut queued = futures.into_iter().enumerate();
            let mut running = FuturesUnordered::new();
            let mut results = Vec::new();
            loop {
                while running.len() < self.concurrency.max(1) {
                    let Some((index, future)) = queued.next() else {
                        break;
                    };
                    running.push(
                        async move {
                            let result = if Instant::now() >= deadline {
                                // Queued work must not start network requests after the deadline.
                                drop(future);
                                tokio::time::timeout_at(deadline, std::future::pending::<T>()).await
                            } else {
                                tokio::time::timeout_at(deadline, future).await
                            };
                            (index, result)
                        }
                        .boxed(),
                    );
                }
                let Some(result) = running.next().await else {
                    break;
                };
                results.push(result);
            }
            results.sort_unstable_by_key(|(index, _)| *index);
            tracing::debug!(
                upstreams = results.len(),
                concurrency = self.concurrency,
                elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
                timed_out = results.iter().filter(|(_, result)| result.is_err()).count(),
                "upstream batch completed"
            );
            results.into_iter().map(|(_, result)| result).collect()
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn bounds_concurrency_and_preserves_input_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks = (0..6).map(|i| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                let _guard = Active(active);
                peak.fetch_max(count, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(if i % 2 == 0 { 10 } else { 1 })).await;
                i
            }
            .boxed()
        });
        let results = AggregationPolicy {
            concurrency: 2,
            timeout: Duration::from_secs(2),
        }
        .collect(tasks.collect())
        .await;
        assert_eq!(
            results.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5]
        );
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deadline_keeps_completed_work_and_drops_pending_work() {
        let active = Arc::new(AtomicUsize::new(0));
        let tasks = [true, false, true].into_iter().map(|hang| {
            let active = active.clone();
            async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = Active(active);
                if hang {
                    std::future::pending::<()>().await;
                }
                42
            }
            .boxed()
        });
        let results = AggregationPolicy {
            concurrency: 2,
            timeout: Duration::from_millis(20),
        }
        .collect(tasks.collect())
        .await;
        assert!(results[0].is_err());
        assert_eq!(results[1].as_ref().unwrap(), &42);
        assert!(results[2].is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn queued_work_is_not_started_after_the_deadline() {
        let started = Arc::new(AtomicUsize::new(0));
        let tasks = (0..4)
            .map(|_| {
                let started = started.clone();
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                .boxed()
            })
            .collect();
        let results = AggregationPolicy {
            concurrency: 1,
            timeout: Duration::from_millis(20),
        }
        .collect(tasks)
        .await;
        assert!(results.iter().all(Result::is_err));
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }
}
