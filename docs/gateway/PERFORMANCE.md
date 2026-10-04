# Performance and tuning

Gateway initialization and catalog discovery contact upstreams concurrently.
The defaults allow eight upstream operations at a time and a ten-second batch
deadline. Start with these settings and measure a representative workload before
changing them. Higher concurrency puts more load on upstream services.

`tools/list` refreshes upstream catalogs on each request. Tool calls reuse a
bounded routing catalog, so repeated discovery and repeated calls have different
costs. Large tool catalogs, authentication policies, quotas, and slow upstreams
all affect latency and resource usage.

For configuration variables, cache limits, and partial-upstream behavior, see
[request concurrency and cache lifetime](ARCHITECTURE.md#request-configuration-concurrency-and-cache-lifetime).

## Measure a deployment

Include realistic catalog sizes, concurrent clients, tenant counts, and upstream
response times. Check initialization, discovery, and tool-call latency separately.
Monitor Gateway memory, database load, and upstream errors during sustained load
and service restarts. Local fixture results are not production capacity limits.

## Development checks

The release-build benchmark requires Linux and Docker and uses disposable services:

```bash
make bench-v1
make bench-v1 BENCH_SAMPLES=50 BENCH_OUTPUT=/tmp/gateway-benchmark.json
```

It measures latency, SQL statements, and Gateway memory for profiles with 1, 10,
and 50 upstreams at several concurrency levels. Output goes to
`output/benchmarks/v1.json` unless overridden. Compare results from the same host
and configuration; the fixture uses synthetic upstream delays and a single client.

For concurrent tenants, large catalogs, and recovery after upstream or Gateway
restarts:

```bash
cargo test -p unrelated-mcp-gateway --test integration_load_recovery -- --ignored --nocapture
```
