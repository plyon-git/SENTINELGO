# SENTINELGO

**Parrish Lyon | PL-SENTINELGO-20260914**

Native Go rendition of SENTINEL's transaction-analysis backend and synthetic-order generator. Runs as a command-line application or a single binary with an embedded browser dashboard. No Python, Flask, Polars, AI API, database, npm build, or third-party Go module is required.

This is a new Go implementation, not a byte-for-byte translation or a reproduction of the unfinished legacy interface. Read [porting notes](docs/PORTING.md) for the source snapshot and intentional differences.

## Run locally

Install a currently supported Go toolchain. The source language minimum is Go 1.23.

```sh
git clone https://github.com/plyon-git/SENTINELGO.git
cd SENTINELGO
go run ./cmd/sentinelgo serve
```

Open **http://127.0.0.1:8080**. Choose a CSV and run analysis. The application has no external fonts, JavaScript CDNs, analytics, license server, or AI calls. Browser results and API tokens are kept in memory, not localStorage.

```sh
mkdir -p bin
go build -trimpath -o bin/sentinelgo ./cmd/sentinelgo
./bin/sentinelgo version
./bin/sentinelgo verify -root .
./bin/sentinelgo serve -verify
```

The compiled binary embeds the dashboard, owner identity, and source integrity baseline. It can run without the source directory unless `verify` or `serve -verify` is requested.

## Generate and analyze a dataset

```sh
./bin/sentinelgo generate -rows 200000 -seed 42 \
  -end 2026-09-14T00:00:00Z -output realistic_orders.csv
./bin/sentinelgo analyze -input realistic_orders.csv -output analysis.json
```

Use the same seed **and end timestamp** for reproducibility within this Go version. Existing output files are never overwritten. `-labels` adds `is_fraud` for synthetic evaluation; the analyzer never uses that label in scoring. Generator defaults reproduce the supplied ten-column layout and 200,000-row target. The source's 1.8% injection target is not an exact measured fraud-label rate because its injected pool includes legitimate ATO precursor rows and is sampled. A generation summary reports the actual labeled count to stderr.

## Analysis coverage

Card-testing velocity, per-user account takeover, BIN/IP bursts, device sharing, disposable-email and static IP-range signals, first-window IP/card clustering, weighted risk scores, aggregate statistics, schema mapping, and exact-input SHA-256 hashing. Results include the owner watermark and the configuration snapshot used.

The source grade order is deliberately retained: **CRITICAL RISK > INVESTIGATE > HIGH RISK > LOW RISK** by numeric threshold (6/4/2/0). This is unconventional; it is not silently reordered.

The web interface displays up to 200 flagged records. JSON responses include up to 5,000 by default; total counts/statistics cover all accepted rows. Set `-max-results 250000` to return all possible flagged rows. Truncation is explicitly identified in the response. No customer data is committed to this repository.

## Input and API

Required logical fields: `timestamp`, `user_id`, `order_value`, `ip_address`, `card_fingerprint`. Common Shopify, Stripe, and generic aliases are recognized. Optional fields: email, device, country, order ID, item ID. Missing required columns, malformed records, invalid timestamps, non-finite/negative amounts, and apparent raw card numbers are rejected. Supply tokens, not PANs. Amounts retain their input units: **no automatic cents conversion, FX conversion, or currency inference**.

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Health and build identity |
| `GET /build` | Owner, version, source commit, manifest hash |
| `POST /upload` | Analyze multipart field `file` |
| `POST /mapping/preview` | Validate full bounded CSV and return mapping/hash |
| `GET /config` | Read the current configuration |
| `POST /config` | Validated partial configuration update, admin token required |
| `POST /set_mode` | `{"demo_mode":true}` or false, admin token required |

```sh
curl -F 'file=@realistic_orders.csv' http://127.0.0.1:8080/upload
```

Uploads are limited to 64 MiB and 250,000 rows, with one active analysis/preview per server instance. Decoding streams, but analysis retains rows for sorting and grouping. This is **not** an unbounded or constant-memory processing service.

## Security and watermark

Local-only binding is the default. Binding to a non-loopback address requires `SENTINEL_API_TOKEN` of at least 32 bytes. Set a separate `SENTINEL_ADMIN_TOKEN` to enable configuration writes; they are otherwise disabled. For remote access, use a TLS reverse proxy and `Authorization: Bearer <token>` for API requests. Admin writes additionally require `X-Sentinel-Admin-Token`. Tokens are supplied through environment variables, never committed.

Source headers, UI attribution, build metadata, response headers, generated reports, `NOTICE`, CODEOWNERS, and `WATERMARK.json` carry Parrish Lyon attribution. `verify` checks source hashes and manifest bytes against the baseline embedded in the binary. It does not establish copyright ownership, stop someone editing copied source, or constitute an external digital signature. No hidden callbacks, telemetry, destructive lockouts, or remote kill switches are present.

[Security boundaries](docs/SECURITY.md) describe remaining deployment requirements. CODEOWNERS is included; GitHub branch protection is not configured by this source repository.

## Tests

```sh
go test -race ./...
go vet ./...
node --check web/app.js   # Optional JavaScript syntax check; Node is not needed at runtime.
go build -trimpath -o bin/sentinelgo ./cmd/sentinelgo
./bin/sentinelgo verify
```

GitHub Actions runs the same Go test, vet, build, and watermark checks. Workflow actions are pinned to commit SHAs and have read-only repository permissions.

## Scope

This rendition provides the analysis engine, generator, API, and a new compact dashboard. It does not include the old case-management, persistent watchlist, full reporting suite, SAR filing UI, or geographic maps. Impossible-travel was a placeholder in the supplied backend and remains explicitly unsupported. No fake geolocation, mock hashes, randomized confidence values, or compliance PASS claims are generated.

Copyright (c) 2026 Parrish Lyon. All rights reserved. See NOTICE for source attribution.
