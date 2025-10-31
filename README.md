# Sentra Backend

## Overview

Backend services for the Sentra stack.

## Development

```
make dev
```

## Indexer Architecture

The off-chain ERC-4337 indexer runs alongside the HTTP server and is split into two
packages:

- `internal/indexer/pipeline`: subscribes to EntryPoint events, decodes logs, and
  persists them through a write worker pool. The pipeline maintains a per-chain log
  cursor and supports chunked backfill, safe-head polling, and graceful shutdown.
- `internal/indexer/service`: read-only facade that exposes status, listings, details,
  paymaster views, sender/contract reports, and overview statistics on top of the
  indexed data. API handlers can depend on this package to build query endpoints.

Pre-built helper scripts/tests:

- `scripts/show_indexer_tables.sh` – convenient SQLite snapshot of all indexer tables.
- `go test ./internal/indexer/...` – verifies pipeline persistence and service queries
  using in-memory SQLite fixtures.

### Implemented Capabilities

- [x] Chunked backfill with safe-head polling and resumable log cursors
- [x] Event decoding for UserOperation, AccountDeployed, Sponsored, revert reasons
- [x] Worker-pool fan-out/fan-in pipeline with graceful shutdown semantics
- [x] Read service exposing status, paginated listings, detail, and aggregated stats
- [x] SQLite schema & repository queries for indexer data (+ helper CLI script)

### Configuration

Indexer runtime knobs are controlled via environment variables (see `.env.example`):

- `INDEXER_ENABLED` – toggles the pipeline.
- `INDEXER_CHUNK_SIZE`, `INDEXER_POLL_INTERVAL`, `INDEXER_CONFIRMATIONS` – control
  range fetching and safe-head behavior.
- `ENTRY_POINT_DEPLOY_BLOCK` – backfill starting point, combined with the persisted
  log cursor for idempotent resumes.

### Database Schema

The indexer stores decoded data into dedicated tables:

- `user_operation_events` and `user_operation_reverts`
- `account_deployments`, `simple_account_initializations`, `sponsorships`
- `log_cursors` for resuming ingestion safely
- `indexer_metrics` (extensible for Prometheus-style metrics)

Queries for API consumption live in `internal/store/indexer_queries.go` and are
surfaced via the service layer described above.
