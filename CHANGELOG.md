# Changelog

All notable changes to the Python `sether` package are documented here. This
package follows [Semantic Versioning](https://semver.org/).

## [0.4.1] - 2026-10-18

Documentation only. No code changes; the published API and behaviour are identical to 0.4.0.

- **README rewritten.** It now has:
  - animated illustrations of the engine
  - a "why this exists, and why now" section, where every figure links to its source
  - a four-step explanation of how the engine works, and the Sether family of tools
- **Corrections:**
  - the parity note no longer calls the TypeScript engine "audited"
  - the NER note points at the early TypeScript-only `@raeven-co/sether-ner`
- **Release process.** Releases are published from CI through PyPI Trusted Publishing; no API token is stored. 0.4.0 was the first release published this way.

## [0.4.0] - 2026-10-17

Security fix. The new API is additive; Sether's own SSE, httpx, ASGI, WSGI and
SDK-wrapper restore paths change output only where they used to splice an
original into JSON as text (see "Fixed" below). Mirrors TypeScript
`@raeven-co/sether` 0.8.0. This is also the first PyPI release of the 0.3.0
changes below: 0.3.0 was tagged but never published to PyPI.

### Security

- `restore_sync` (and `Sether.restore_sync`) on **serialized JSON** inserts
  original values unescaped. An original containing `"` can add keys to the
  document: a name of `Alice", "bcc": "attacker@example.com` restored into
  tool-call arguments adds a `bcc` recipient. An original ending in `\` breaks
  the document, and the built-in labeled-password and address detectors can
  capture a trailing backslash. Default behaviour is unchanged; code that
  restores JSON must switch to `restore_json` / `restore_json_value`.

### Added

- **`restore_json(text, vault, *, strict=False)`** and
  **`Sether.restore_json(text, *, strict=False)`**: parse the document, restore
  each string value on its own and re-serialize (compact), so `json.dumps`
  escapes originals. Object keys are never restored. Invalid JSON raises
  `json.JSONDecodeError` and a non-string raises `TypeError`; there is no
  fallback to text replacement.
- **`restore_json_value(value, vault, *, strict=False)`**: the same for an
  already-parsed value. Returns a new value and does not mutate the input.
- **Strict mode**: the `strict` keyword on `restore_sync`, `Sether.restore_sync`,
  `restore_json` and `restore_json_value` raises `UnresolvedTokenError` (a
  `ValueError`) listing every token-shaped string that would be left in place:
  unresolvable tokens, case-altered copies (`<email_...>`) and tokens in keys.
  The error carries tokens only, never originals.
- `TOKEN_RE` and `JsonValue` are exported from the package root (`TOKEN_RE` was
  previously only in `sether.stream`).
- **`restore_tool_arguments=False`** on `wrap_openai` / `wrap_anthropic`.
  Opt-in, so tool-call arguments still stay tokenized by default (tests pin
  this). When `True`, non-streaming
  `choices[].message.tool_calls[].function.arguments` are restored value by
  value (left tokenized if not valid JSON), and `tool_use` `input` through
  `restore_json_value`. Restored arguments carry real PII into tool code;
  validate them before acting.

### Fixed

Sether's own restore paths no longer splice originals into JSON. They restore
JSON value by value, in place: only the string values that hold a token are
decoded, restored and re-encoded, so every other byte is kept (formatting, key
order, escapes and numbers). Object keys are never restored. Output changes
only where a restored value is re-escaped, a token was escaped as
`\u003c...\u003e` (now restored), a token sat in a key (no longer restored), or
JSON-mode content is not valid JSON (now left tokenized).

- `sse_restore_iter` / `create_sse_restore_stream`: a `data:` payload that
  parses as JSON is restored value by value, so an original containing `"`,
  `\` or a line break can no longer change the chunk or inject SSE lines. Other
  payloads (`[DONE]`, plain text) are still restored as text. The strict
  `xfail` marker is gone.
- `sse_restore_iter` / `create_sse_restore_stream`, and `wrap_httpx`,
  `SetherASGIMiddleware` and `SetherWSGIMiddleware` on an `event-stream` body:
  in a `data:` payload that is not JSON, a line break (`\n`, `\r` or `\r\n`) in
  an original used to end the line, so the rest of the original could inject
  `event:` / `id:` / `data:` fields or a blank line that dispatches the event
  early. The original now continues on a new `data: ` line, in the line ending
  of the stream. The client joins data lines with `\n`, so CR and CRLF in an
  original arrive as `\n`. Output is byte-identical when no original has a
  line break.
- `wrap_httpx`, `SetherASGIMiddleware`, `SetherWSGIMiddleware`: `event-stream`
  bodies are restored per `data:` payload; a body that parses as JSON value by
  value; a JSON-typed body that doesn't (NDJSON, JSON Lines) line by line, with
  lines that are not valid JSON left tokenized so an original can't complete a
  truncated document into a different one; other text as text.
- `wrap_openai` / `wrap_anthropic`: when the request asks for JSON output
  (`response_format` `json_object` / `json_schema`; Anthropic
  `output_config.format` or the deprecated `output_format` with `json_schema`),
  `message.content` / text blocks are restored value by value, and left
  tokenized if they aren't valid JSON. Streamed JSON-mode deltas are fragments
  of a document and now stay tokenized instead of being restored as text.

### Changed

- PyPI project links now point at this repository (`emorilebo/sether-py`) and
  the live site, `sether.raevenmarket.com.ng`.

### Known issues

- JSON-mode output streamed over SSE (`sse_restore_iter`, or a middleware on an
  event-stream body): each chunk stays valid, but the `delta.content` fragments
  join into a second JSON document the stream can't see. Collect the tokenized
  fragments and call `restore_json` on the result.
- `restore_sync` and the restore streams are text substitution by design.
- `AliasVault.restore()` is plain substitution as well; the README says to apply
  it per parsed string value on JSON.

## [0.3.0] - 2026-08-13

Tagged but never published to PyPI; these changes first ship in 0.4.0.

Mirrors TypeScript `@raeven-co/sether` 0.7.0 — detection-gap fixes from a
Sether Shield field report, plus the new alias engine.

### Added

- **Alias engine** (`alias_value`, `suggest_aliases`, `shape_alias`,
  `AliasVault`). Replace a detected value with a realistic decoy instead of a
  mask — names become John Doe-style names, phones become officially-fictional
  numbers (US 555-01XX, Ofcom 07700 900XXX), emails move to RFC 2606 domains,
  cards are Luhn-valid, API keys keep their vendor prefix with a scrambled
  tail — then reverse it later with `AliasVault.restore()`, including on AI
  replies that echo the decoy. Same-original → same-alias within a vault;
  aliases are vault-unique by construction. Randomness injectable for tests.
- **`create_multi_region_phone_detector(countries)`** — one PHONE detector
  covering several regions' national formats at once, de-duplicated by span.
- **Label-anchored secrets** (`labeled_api_key_detector`,
  `labeled_password_detector`) — catches `my api key is AbC123…` (below the
  entropy floor, no vendor prefix) and `password: hunter2butlonger`, with
  validators that keep "api key management" / "password is required" clean.
  Both included in `secrets_detectors`.

### Fixed

- DOB: `born on 14/03/1995` now anchors (previously only bare `born`).
- Address: conversational anchors (`I live at …`, `deliver to …`) and
  Commonwealth street suffixes (crescent/cres, gardens/gdns, grove, mews,
  estate); verb-shaped suffixes deliberately excluded from standalone
  detection.
- Address false positive: `my email address is x@y.com, call 0806…` was
  detected as one giant ADDRESS match swallowing the whole line — non-postal
  "address" compounds (email/IP/MAC/wallet/server/…) no longer anchor the
  detector.

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
