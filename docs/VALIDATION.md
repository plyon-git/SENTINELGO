# Validation record

Parrish Lyon / PL-SENTINELGO-20260914 / 2026-09-14.

## Completed locally

- Go 1.23.2, Linux AMD64: all 29 top-level Go tests passed, including CSV edge-case subtests.
- `go test -race ./...`: passed, including concurrent configuration/read/upload tests.
- `go vet ./...`: passed.
- `node --check web/app.js`: passed.
- Linux AMD64 native build: passed and executed.
- macOS ARM64 and Windows AMD64 cross-compilation: passed. Those target binaries were not executed in their respective operating systems.
- Source integrity verifier: passed for the final source baseline; tests reject changed files, missing files and altered owner metadata.
- HTTP handler integration tests: CSV upload, mapping preview, authentication, admin validation, Host/origin checks, static assets and expected error methods passed.

## 200,000-row synthetic exercise

Fixed seed 42, end timestamp 2026-09-14T00:00:00Z. CSV size: 24,749,866 bytes. The native generator emitted exactly 200,000 transactions; the native analyzer accepted all 200,000 and its risk counts reconciled to that total.

| Classification | Count |
| --- | ---: |
| Critical risk | 68 |
| Investigate | 4,290 |
| High risk | 1,193 |
| Low risk | 194,449 |
| Total flagged | 5,551 |

The default JSON cap returned 5,000 flagged records with `flagged_rows_truncated: true`. Generator summary reported 3,255 synthetic fraud labels. This is not a precision/recall evaluation or a claim that the flagged count equals fraud: the generator sampling behavior and detector heuristics are described in PORTING.md.

Observed in this single development run: generation 0.43 seconds; analysis 1.75 seconds; analysis peak resident memory approximately 301 MiB. These are environment-specific observations, not benchmark guarantees or a production capacity claim.

## Not established

A Chromium end-to-end UI check was attempted but this environment blocked navigation with `ERR_BLOCKED_BY_ADMINISTRATOR`. Browser interaction and rendering have therefore not been fully end-to-end validated. JavaScript syntax and server-side static-asset delivery were validated separately.

No exhaustive Python/Go parity suite, real-world fraud-model calibration, penetration test, compliance certification, signed release attestation, or production hosting was performed. GitHub Actions status must be checked independently for the published commit.
