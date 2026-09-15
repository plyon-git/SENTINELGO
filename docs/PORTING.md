# Porting record

Owner watermark: Parrish Lyon / PL-SENTINELGO-20260914.

## Sources

- Supplied `generate_orders_large(2).py`: native synthetic generator basis. Its original header credits **Ledgewell Data Team**.
- Supplied `app(2).py`, `ledgewell_file_map(2).txt`, `README(5).md`, `requirements(2).txt`, `vercel(2).json`: original structure, launcher, dependencies and Flask/Vercel routing.
- `plyon-git/SENTINEL` main snapshot `d402e89f2f826171161471462f81a6abdff0f397`: six uploaded files with Parrish Lyon watermarks.
- Actual backend source: `plyon-git/SENTINEL` migration snapshot `ad9a0a62455da2a0eb432bfa3747b5ba2a0afe9c`, `backend/{config,schema_mapper,utils,fraud_detector,routes,app}.py`. That snapshot records upstream `iohins/ledgewell-sentinel@33b0697a47ecdaf2cc152f39c1d37e50e87f2917`.

Source files are not altered in either existing repository. Attribution records provenance, not a legal determination about ownership or employment disputes.

## Native counterparts

| Python responsibility | Go implementation |
| --- | --- |
| Flask app and routes | `server.go`, `cmd/sentinelgo/main.go` |
| Config and demo presets | `config.go` |
| CSV input and schema mapping | `csv.go` |
| Enrichment, detectors, scores, clusters | `engine.go` |
| Synthetic orders | `generator.go` |
| Source attribution and integrity | `identity.go`, `WATERMARK.json` |
| Browser UI | New embedded `web/` dashboard |

The generator preserves profile-based spending, source country/device/email weights, 90-day timing, card-testing, ATO, triangulation and friendly-fraud injection, sampling of the injected pool, final shuffling, and ten-column output. Random streams differ from Python. Defaults use seed 1; a fixed end timestamp is also required for deterministic reproduction. Unlike the Python source's simulated PAN construction, Go fingerprints hash random bytes and never construct card numbers. Random non-datacenter public addresses use the documentation range 203.0.113.0/24. Times are clamped to the end of the generation interval. Empty fraudster/legitimate candidate pools have safe fallbacks.

## Deliberate behavior differences

1. **Validation instead of fabricated values.** Required fields are rejected when missing. The Python mapper inserts unknown users/cards, current timestamps and zero amounts. Go does not use arbitrary numeric columns as amounts. Matching uses normalized exact aliases, not the Python fuzzy/sample heuristics. Negative amounts/refunds are outside this rendition's accepted schema.
2. **Card-testing elapsed-time gate.** Both implementations consider the most recent N values per card. Go additionally enforces `velocity_window_minutes`; the source computes a last-N rolling mean without enforcing its advertised time window.
3. **BIN rates use fractional hours.** The source applies integer total-hours truncation before its 0.1-hour floor to per-IP spans. Go uses fractional hours for both IP and global rates.
4. **Defined non-cluster scores.** Go adds zero cluster weight when a transaction has no cluster, avoiding possible null propagation through the source's Polars expression. Tests assert unclustered amounts still score.
5. **Unknown is not adverse evidence.** Missing device information does not create an ATO device-change signal. Invalid, reserved, loopback and private IPs are excluded from public-IP clustering/BIN rules. CIDR/domain lists are static source heuristics, not verified live intelligence.
6. **Deterministic clusters.** First-window grouping and IP-before-card priority are retained. Keys are considered in stable time-of-first-observation order rather than unspecified hash-group order; IDs can differ. IP unique-user minima are enforced inside the cluster window.
7. **Safer API contracts.** No arbitrary Config attribute mutation, public wildcard CORS, developer debug service, fabricated mapping confidences, or raw exception details. Configuration updates are validated/locked and each analysis uses its own snapshot.
8. **Bounded responses.** Results include the total flagged count and an explicit truncation flag. Only capped flagged rows are serialized; aggregate statistics remain complete. Source synthetic truth labels are not scoring features.
9. **New interface, not legacy feature parity.** HTML/CSS/JavaScript is embedded into the Go executable. It directly calls the Go engine and does not port the separate legacy JavaScript scoring implementation or mock analytical displays.
10. **Deployment changes.** The Flask-specific Vercel config and Python requirements are not copied as Go deployment instructions. Build/run the native binary instead.

These intentional changes mean equivalent CSV input is not promised to produce identical Python and Go flags. Tests exercise specified Go behavior, not an exhaustive Python-versus-Go parity suite. Fraud thresholds are heuristics and have not been calibrated against labeled real-world transaction data.

## Source baseline maintenance

WATERMARK.json lists SHA-256 hashes of released source and documentation, excluding itself. Its exact bytes are embedded in the binary. For an authorized code change, review the diff, recompute the changed entries with a SHA-256 tool, add entries for new source files, rebuild, and run `verify`. Removing an entry weakens coverage and must receive owner review. Preserve a trusted released binary or independently recorded manifest hash outside the editable repository for stronger comparison.
