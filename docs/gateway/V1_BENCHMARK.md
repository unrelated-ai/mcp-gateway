# v1 performance baseline

Measured locally on 2026-09-07. These are controlled fixture measurements, not
production capacity or latency guarantees.

## Setup and reproduction

```bash
make bench-v1
# Optional output location and sample count:
make bench-v1 BENCH_SAMPLES=10 BENCH_OUTPUT=/tmp/v1-benchmark.json
```

The ignored Rust benchmark requires Linux and Docker and refuses a debug build.
It uses a release Gateway, disposable PostgreSQL 16 with `pg_stat_statements`, and
50 separate loopback listeners running rmcp 2.2.0 in sessionless JSON-response mode.
Each configured upstream contributes one tool and waits 20 ms on initialization
and discovery. The listeners share one fixture process. The host was an AMD Ryzen
7 9800X3D, with 16 logical CPUs available.

Each profile size (1, 10, 50 upstreams) is measured with concurrency 1, 8 and 16.
There are 10 samples per phase/configuration, 450 samples per run. Every iteration
starts a fresh Gateway. Cold initialize includes `notifications/initialized`;
cold discovery is its first `tools/list`. Warm discovery repeats that request,
warm call uses the discovered route, and warm initialize opens another session
against the same process. The rmcp transport client deliberately has no background
GET stream, so the recorded operation has clear query-count boundaries.

The profile uses disabled data-plane auth and no quotas or rate limits. Statement
counts cover the Gateway's dedicated database role, excluding the observer and
provisioning role. They include BEGIN/COMMIT where used, activity writes and any
background statements that overlap an operation. Other auth/limit policies add
work. RSS is sampled from the Gateway process after each operation; it excludes
PostgreSQL, the fixture and the client.

Raw samples:

- [Before activity batching](benchmarks/2026-09-07-before-activity-batch.json): application source `2d4300f`; recorded checkout `3a95f89`.
- [After activity batching](benchmarks/2026-09-07-after-activity-batch.json): application source `47e24cf`; recorded checkout `e2de1e0`.

Both runs use the benchmark harness from `8fb747a`. The application-source
revisions above contain the same Gateway code as their recorded checkouts;
raw files retain the original checkout IDs and measurements. The host was not
isolated, and the benchmark uses a single client. A reported p95 is the
nearest-rank value from only 10 observations (therefore the maximum); use larger
runs before choosing an SLO.

## Latency with the default concurrency of 8

Post-batching milliseconds: median, with sample p95 in parentheses.

| Upstreams | Cold initialize | Warm initialize | Cold discovery | Warm discovery | Warm call |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 40.5 (43.4) | 35.2 (42.8) | 28.4 (31.4) | 27.9 (29.7) | 6.9 (8.1) |
| 10 | 69.7 (74.3) | 60.7 (61.3) | 51.1 (52.8) | 50.1 (51.2) | 8.6 (10.2) |
| 50 | 197.5 (202.5) | 173.6 (174.3) | 160.2 (163.1) | 160.5 (184.7) | 10.5 (11.3) |

`tools/list` deliberately refreshes upstream catalogs on every request. Warm
results reuse connections and endpoint data; they are not cached catalog responses.
Tool calls do reuse their per-session routing catalog.

## Database improvement found during the baseline

Activity tracking previously opened a transaction and issued one upsert for every
bound upstream on each request. The batch replaces those writes and explicit
BEGIN/COMMIT with one atomic `INSERT ... SELECT ... ON CONFLICT` statement. It
preserves all bound endpoints' drain-visibility timestamps and deduplicates pairs.
The integration test verifies both bindings are refreshed together without adding
rows on a subsequent call.

Median statement counts with concurrency 8, shown as **1 / 10 / 50 upstreams**:

| Phase | Before | After |
| --- | ---: | ---: |
| Cold initialize | 19 / 82 / 362 | 15 / 60 / 260 |
| Warm initialize | 17 / 62 / 263 | 13 / 40 / 161 |
| Cold discovery | 8 / 26 / 106 | 6 / 15 / 55 |
| Warm discovery | 8 / 26 / 106 | 6 / 15 / 55 |
| Warm call | 7 / 16 / 56 | 5 / 5 / 5 |

At 50 upstreams, warm calls dropped from 56 to 5 statements. Local call latency
changed only modestly: this is a measured reduction in database work, not a claim
of an equivalent latency speedup. Initialization counts include both initialize
and its following notification.

Discovery still checks the tenant-local source catalog once per attached source
before treating the source as a remote upstream (`TenantCatalog::has_tool_source`).
That explains the remaining N + 5 discovery statements in this setup. A batch
source-classification API is a sensible next optimization, especially with a remote
database. It should preserve the precedence of tenant-local, shared and remote
sources, rather than caching away configuration changes.

## Concurrency and memory decisions

Post-batching warm discovery medians (ms):

| Upstreams | Concurrency 1 | Concurrency 8 | Concurrency 16 |
| ---: | ---: | ---: | ---: |
| 1 | 27.9 | 27.9 | 27.8 |
| 10 | 220.5 | 50.1 | 29.2 |
| 50 | 1072.6 | 160.5 | 96.3 |

Keep the default of **8**. Sixteen reduces batch latency for the larger synthetic
profiles, but this single-client run does not establish the effect of twice as
many simultaneous upstream requests under load. Operators can opt into 16 after
measuring their own upstreams. Keep the 10-second batch deadline: these fast local
fixtures do not justify reducing a timeout for real tools or networks. Separate
acceptance tests verify that a configured 1-second deadline bounds slow upstream
initialization and discovery and honors partial/strict profile behavior.

Peak sampled Gateway RSS at concurrency 8:

| Upstreams | Before (MiB) | After (MiB) |
| ---: | ---: | ---: |
| 1 | 21.4 | 21.4 |
| 10 | 22.4 | 22.3 |
| 50 | 24.6 | 24.6 |

These runs use small catalogs and only two sessions per Gateway process. They do
not test a full 4096-entry cache or establish a safe byte budget. Retain the
existing cache defaults pending a separate session-churn/large-catalog load test.
