# v1 release-candidate validation

Validation record for `feat/version_one_zero` as of 2026-09-07.
v1 release artifacts are pending publication.

## Candidate changes

- Tenant managed-deployment routes and profile CRUD routes now have separate
  modules. Profile validation and update planning are independent of HTTP
  responses and persistence.
- Explicit JSON `null` now clears profile descriptions and tool timeouts through
  both tenant and admin APIs. Omitted fields retain their documented behavior.
- The real `unrelated` client and compact stdio proxy work through the Gateway with
  a sessionless rmcp upstream and a real Adapter-backed stdio service.
- Restart tests reuse one client connection and verify its exact signed session
  token across two Gateway replicas and a Gateway restart. Replacing a sessionless
  upstream at its bound URL works without initializing it again.
- Slow upstream initialization/discovery is bounded by the configured batch
  deadline; healthy sources remain usable when partial upstreams are allowed.
- Session activity is written in one atomic batch. The measured warm-call database
  count is now constant across 1, 10 and 50 upstreams in the benchmark configuration.

v1 also includes MCP OAuth resource-server support, the `unrelated` CLI,
sessionless upstream bindings, shared request configuration, bounded caches, and
bounded parallel upstream operations. See [the upgrade guide](V1_UPGRADE.md) and
[architecture](ARCHITECTURE.md) for the complete feature set.

## Rehearsal evidence

The public 0.13.1 image used for the rehearsal has digest
`sha256:dc4f2750df6526e65bb83b7b83e37f8aa47e8ff6d5f33562d67e5f5ffb157ea9`
and source revision `173f44e9a37bf16d78014dfbb63bfcce9c6a788e`. Its extracted
release executable was run against a disposable PostgreSQL database with the
pre-v1 migrations. All earlier migration files match that release; the only new
migration is `20260712000000_oauth_resource_server.sql`.

The automated rehearsal:

1. Created a tenant, profile and API key using the public executable.
2. Initialized and called a real Adapter-backed stdio tool.
3. Stopped the old Gateway before applying the new migration.
4. Verified the original profile settings, tenant token and API key on v1.
5. Called a tool using the signed routing token issued by 0.13.1.
6. Verified that API-key credentials are now required on subsequent requests.
7. Attached a sessionless rmcp server and called both upstreams with the real CLI.

Chromium validation against the migrated database covered tenant unlock,
profile loading, surface probing, API-key listing, and profile edits. Renaming
a profile and clearing its description and timeout persisted after reload and
direct API verification. The existing 0.13.1 key remained visible. No browser
console errors or failed API requests were observed.

The browser check used a production build served by `next start`. Deployment
packaging uses the standalone server and requires an artifact smoke test.

## Performance baseline

The [performance report](V1_BENCHMARK.md) includes raw before/after samples,
methodology, query counts, memory measurements and the decision to retain current
defaults. It is a single-client baseline, not a capacity test.

## Repeatable checks

```bash
make ci
make test-gateway-contracts
make test-v1-journey
MCP_GATEWAY_0131_BIN=/path/to/public/gateway-0.13.1 make test-v1-upgrade
make bench-v1
cd ui && npm test && npm run lint && npm run build
```

The Rust workspace checks, PostgreSQL contracts and real-client tests are covered
by the Rust CI workflow. The public-binary
upgrade rehearsal and release benchmark remain explicit local/release checks;
they do not silently run or download historical images in ordinary unit tests.
See [rehearsal setup](V1_UPGRADE.md#repeat-the-public-release-rehearsal).

## Validation results

The following checks passed locally. Remote CI results are tracked separately
by the workflow runs for each revision.

| Check | Result |
| --- | --- |
| Rust workspace formatting, Clippy and tests (`make ci`) | Passed |
| PostgreSQL contracts | 15 tests passed |
| Tenant API integration | 10 tests passed |
| Real-client and restart scenarios | 2 tests passed |
| Public 0.13.1 upgrade | Passed |
| UI unit tests | 5 tests passed |
| UI production build and lint | Passed |
| Performance benchmark | 450 samples completed in each of two runs |

## Before tagging or deploying the RC

- Select the RC version and update component/chart versions and release notes
  according to the release workflow.
- Build matching Gateway, migrator, UI, Adapter and CLI artifacts from the reviewed
  revision. Smoke-test the packaged images/standalone UI and the intended ingress
  or load balancer. Local binary and proxy tests do not cover image packaging
  or deployment-specific routing.
- If using OAuth, complete a login/token flow against the actual issuer and check
  the profile URL audience and required scopes. The local acceptance fixtures
  do not cover a live issuer.
- Back up the database and keys; rehearse restoring that backup. The automated test
  used a disposable database and did not exercise an operator's backup system.
- Schedule a maintenance window, stop all old Gateway replicas and pause writes,
  run the matching migration, then start the v1 replicas. Do not mix old and new
  Gateway versions across this authentication-mode migration.
- Verify representative profiles and clients before resuming traffic. A stateful
  upstream still owns its own sessions; an upstream restart may require client
  reinitialization. Sessionless tokens still bind a chosen endpoint, with no
  automatic endpoint reselection or replay of failed tool calls.

## Performance considerations

Discovery performs one tenant-local catalog lookup per attached upstream;
batching source classification could reduce this database work. Concurrent-client,
large-catalog and session-churn measurements are needed before changing cache
entry limits or default concurrency.
