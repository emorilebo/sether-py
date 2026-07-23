# Changelog

All notable changes to the Python `sether` package are documented here. This
package follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-16

### Added

- **JSON / structured-data key detection** for the identity pack. `name_detector`,
  `dob_detector`, `passport_detector`, and `address_detector` now also fire on a
  JSON-style key whose name contains the class word, e.g. `"customer_name": "..."`,
  `"date_of_birth": "..."`, `"passport_number": "..."`, `"billing_address": "..."`
  (snake/kebab/camel/spaced). Value validators reject non-PII, so a loose key match
  cannot over-fire; the `"key":` shape means prose is unaffected. Mirrors the
  TypeScript `@raeven-co/sether` 0.6.0 change. Opt-in `identity_detectors` only.

## [0.1.1] - 2026-07-03

### Added

- `create_phone_detector(default_country=...)` — build a PHONE detector that
  also catches **national-format** numbers (e.g. `(415) 555-2671`,
  `0803 123 4567`) for a known region. `create_phone_detector()` with no argument
  is identical to the default `phone_detector` (international-format only). Parity
  with the TypeScript `createPhoneDetector`.
- Redaction flow diagram in the README (renders on the PyPI project page).

## [0.1.0] - 2026-06-25

First release of the Python port of `@raeven-co/sether`. Reaches feature parity
with the TypeScript `0.5.x` line.

### Added

- **Core engine.** `Sether` facade with a shared vault wiring redaction and
  restoration. `redact_sync` / `restore_sync` for complete text.
- **Streaming, sync and async.** Chunk-boundary-safe `redact_stream` /
  `restore_stream` (sync iterables) and `aredact_stream` / `arestore_stream`
  (async iterables), plus the low-level `RedactStream` / `RestoreStream`
  transforms. Holds back `safe_distance_bytes` (default 256) at each chunk tail
  and an in-progress whitespace-free run up to `max(safe_distance_bytes * 4,
  8192)` bytes so long secrets are never emitted partially.
- **Basic detector pack:** email, phone (`phonenumbers`), credit card (Luhn),
  SSN (SSA invalid-prefix rules), IPv4, IPv6 (in-tree validator), IBAN (mod-97).
- **Secrets detector pack:** AWS, OpenAI, Anthropic, GitHub (classic +
  fine-grained), Slack, Stripe, JWT, and a Shannon-entropy generic detector.
- **Identity detector pack (opt-in):** label-anchored, multilingual name / DOB /
  passport / address detection with Unicode-aware value capture.
- **Token vault.** In-memory LRU + TTL `MemoryVault`; `Vault` protocol for
  custom stores.
- **SSE / JSON-stream mode.** Redacts `data:` payloads while preserving SSE
  framing verbatim, with sync and async iterator helpers.
- **Audit schema + sinks.** `AuditEvent`, `RegulationMapping`,
  `DEFAULT_REGULATION_MAPPINGS`, `ConsoleAuditSink`, `MemoryAuditSink`. JSON wire
  shape matches the TypeScript package (camelCase). The original value is never
  logged, only its length.
- **Integrations:** `wrap_httpx` (sync + async), `SetherASGIMiddleware`
  (FastAPI / Starlette), `SetherWSGIMiddleware` (Flask), `wrap_openai`, and
  `wrap_anthropic`. The SDK wrappers are structurally typed and never import the
  SDKs.

### Notes

- Detector regexes are compiled with `re.ASCII` so `\b` / `\d` stay ASCII-only,
  matching the audited JavaScript semantics (no Unicode-digit false positives).
- Requires Python 3.9+. 76 tests pass, including a property-based chunk-partition
  round-trip identity check.
