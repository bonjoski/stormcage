# Claude Code Guidelines for `stormcage`


## Build & Test Commands
- **Build Binary:** `go build -o bin/stormcage ./cmd/stormcage`
- **Unit Tests:** `go test -v ./...`
- **Linter:** `golangci-lint run`
- **Scan Text:** `./bin/stormcage scan --input "<text>"`
- **Start Server:** `./bin/stormcage server --port 8181`

## Code Style & Architectural Invariants
- Semantic taint tracking: `TRUST_LOCAL_WORKSPACE`, `TAINT_EXTERNAL_USER`, `TAINT_UNTRUSTED_WEB`.
- NFKC Unicode normalization and zero-width rune stripping (`\u200b`, etc.).
- OWASP LLM01 prompt injection detection: Tier 0 regex + Tier 1 semantic intent-drift vector tracking.
- Sub-0.5ms SHA-256 verdict caching to avoid multi-agent scratchpad bottlenecks.
- Linear-time regular expression evaluation to prevent ReDoS.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
