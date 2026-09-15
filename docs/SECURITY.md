# Security boundaries

Parrish Lyon / PL-SENTINELGO-20260914.

This source is a bounded single-user/internal-tool rendition, not a production security certification.

- The listener defaults to 127.0.0.1:8080. With no API token, only localhost/loopback Host headers are trusted; cross-origin browser requests are denied. Non-loopback bindings require a 32-byte-or-longer API token.
- Remote deployment requires TLS termination, access management, rate limiting, memory/CPU limits and an operational incident plan outside this application. A public GitHub repository is not a hosted production deployment.
- API authentication is optional for loopback use. Configuration writes require a separate admin token and are disabled by default. The static shell and `/health` remain public, but never expose transaction data or tokens.
- The request body and CSV row count are bounded, and only one upload/preview runs at once. Multipart spill files are cleaned up. In-memory analysis and JSON serialization still consume memory proportional to the accepted workload. No indefinite queue, persistent case database, or multi-tenant isolation is provided.
- The browser uses textContent for CSV-derived values and a restrictive CSP, with no external resources or browser persistence. Exported JSON contains selected transaction data and must be protected by the operator. The source scanner is not a formal guarantee that every possible sensitive value has been detected.
- Apparent raw card numbers are rejected. Use properly tokenized data; do not use this tool as a payment-card vault. Fingerprint detection is a heuristic, not PCI validation.
- The Go binary contains public ownership identifiers and an embedded file-hash baseline. These are attribution/tamper evidence only. An attacker controlling source, manifest and rebuild can replace all three. No signing private key is embedded or generated, and no watermark can prevent all reuse of publicly available source.
- `verify` covers listed files and rejects missing/changed files, manifest-byte changes and symlinks on listed paths. It is not a live filesystem monitor, a full package-signing system, or a check of unlisted additions. Run it against a stable, trusted checkout, not a concurrently modified directory.
- No hidden telemetry, external license enforcement, remote kill switch, data destruction or phone-home mechanism is implemented.

Use a supported, patched Go toolchain for deployment. The local development environment used Go 1.23.2 to validate language compatibility; that is not a recommendation to deploy an outdated runtime. CI selects the current stable Go release.
