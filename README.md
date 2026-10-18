<p align="center">
  <img src="https://raw.githubusercontent.com/raeven-co/sether/main/assets/readme/sether-hero.webp" width="840" alt="Animated illustration: Sether spots an email address in a draft, masks it, swaps it for a realistic decoy, then restores the original when the reply comes back.">
</p>

# Sether (Python)

**Keep the context. Protect the details.**

Your AI can help write the email. It doesn't need your actual email address.

Sether is a small, deterministic engine for the boundary between your app and
any model. It finds personal data and secrets in text and swaps them for tokens
or realistic decoys before the text leaves your process. When the reply comes
back, it puts the originals back. It's streaming-safe and JSON-safe, the vault
stays on your side, and the library makes no network calls of its own.

```bash
pip install sether
```

[Live sandbox](https://sether.raevenmarket.com.ng/sandbox) · [Python docs](https://sether.raevenmarket.com.ng/docs/python) · [TypeScript package](https://www.npmjs.com/package/@raeven-co/sether) · [Changelog](https://github.com/emorilebo/sether-py/blob/main/CHANGELOG.md) · MIT

> Named for the Hebrew *sether* (סֵתֶר), "the hiding place" (Psalm 32:7).
> The name is also the spec.

---

## Why this exists, and why now

**AI got useful by reading the real thing.** Support tickets, logs, CRM rows,
contracts. People paste the whole thing because they want a good answer. The
task needs help. The details hitch a ride.

- 77% of employees who use GenAI paste data into it, and 22% of those pastes
  contain personal or payment-card data
  ([LayerX report, via The Register, Oct 2025](https://www.theregister.com/software/2025/10/07/employees-regularly-paste-company-secrets-into-chatgpt/1274532)).
- Harmonic Security counted 579,113 sensitive-data exposures across 22.5 million
  enterprise AI prompts and uploads in 2025
  ([Harmonic, Jan 2026](https://www.harmonic.security/resources/what-22-million-enterprise-ai-prompts-reveal-about-shadow-ai-in-2025)).
- 92% of organisations that had an AI-related security incident lacked proper AI
  access controls
  ([IBM Cost of a Data Breach 2026](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average)).

**Agents raised the stakes.** A chatbot reads your data. An agent acts on it: it
updates the CRM, sends the email, files the ticket. The tool needs the real
address back, so one-way masking breaks the workflow, and a workflow that breaks
tends to get switched off. Hiding the value is the easy half. Giving it back
safely is the hard half. We learned that one the honest way: 0.4.0 (0.8.0 in
TypeScript) fixed our own restore path, where a value restored into tool-call
JSON as plain text could add a `bcc` recipient.

**The rules already apply.**

- An LLM API provider typically acts as your processor, and
  [GDPR Article 28](https://gdpr-info.eu/art-28-gdpr/) expects processors that
  give sufficient guarantees, bound by a contract.
- OWASP lists
  [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
  in its Top 10 for LLM applications.
- In Nigeria, the NDPC fined MultiChoice ₦766.2 million in July 2025, citing
  privacy breaches and unlawful cross-border transfers of personal data
  ([ICIR](https://www.icirnigeria.org/ndpc-fines-multichoice-nigeria-%E2%82%A6766-million-over-data-privacy-violations/)).

**Detection is becoming free, and that's good news.**

- [LangChain's PIIMiddleware](https://docs.langchain.com/oss/python/langchain/guardrails) can redact, mask, hash or block.
- [n8n's Guardrails node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-langchain.guardrails/) swaps PII for placeholders.
- OpenAI released an open-weight [Privacy Filter](https://huggingface.co/openai/privacy-filter) (Apache-2.0) in April 2026.
- [Presidio](https://github.com/data-privacy-stack/presidio), originally Microsoft's and now community-maintained, is a mature detector.

Sether focuses on the part around detection: deterministic, streaming-safe
replacement, a vault you own, and a restore that can't rewrite your JSON. If you
prefer another detector, plug it in as a custom detector.

---

## How the engine works

<p align="center">
  <img src="https://raw.githubusercontent.com/raeven-co/sether/main/assets/readme/sether-round-trip.webp" width="840" alt="Animated diagram of the SDK round trip: your application's text goes through Sether, which swaps the email for a token or decoy and keeps the mapping in your vault; the model works with the placeholder; the reply comes back through Sether and the original email is restored.">
</p>

A stand-in goes out. The original comes back. Four steps, all in your process:

| Step | What happens | The detail that matters |
| --- | --- | --- |
| **1. Detect** | Detector packs scan the text: emails, phones, cards, SSNs, IPs, IBANs by default; secrets and labelled identity fields when you opt in. | Every detector is deterministic (pattern plus validator: Luhn, mod-97, libphonenumber, SSA rules). The same input gives the same output. The patterns are the TypeScript engine's, and every one is ReDoS-checked in that repo's CI. |
| **2. Replace** | Each match becomes a typed token such as `<EMAIL_9f1c…>`, or a realistic decoy from an `AliasVault`. | The original goes into **your** vault (in-memory LRU by default: 10,000 entries, 1-hour TTL). It never goes into the token or an audit event. |
| **3. Stream** | Redaction runs over sync or async iterables of text, so token-by-token LLM traffic works. | The stream holds back a 256-byte tail (and long secrets up to 8 KB), so a value split across two chunks is still caught. Property-based tests split text at random boundaries and check the round trip. |
| **4. Restore** | Tokens or decoys in the reply are swapped back for the originals. | For JSON (tool calls, JSON mode), `restore_json` restores value by value and never touches keys. `strict=True` refuses tokens the vault never issued. |

```text
your app ──► detect ──► replace ──► model sees <EMAIL_9f1c…>
   ▲                       │
   │                 your vault (originals)
   │                       │
   └──── restore ◄─────────┴──── reply mentions <EMAIL_9f1c…>
```

## What Sether is, and isn't

- **It is a boundary, not a model.** No ML runs on the hot path, so results are
  reproducible and testable. For free-text names, pair it with your own NER
  as a custom detector.
- **It keeps your context.** The model still gets the task, the structure and a
  stand-in it can reason about. "Draft a welcome email to `<EMAIL_1>`" is still
  a perfectly good prompt.
- **It is inspectable.** MIT, a wheel of under 60 KB, one runtime dependency
  (`phonenumbers`), published from CI with PyPI Trusted Publishing. Read it, fork it, audit it.
- **It is honest about misses.** Detection is pattern-based. It will miss
  things it has no pattern for, and dense numbers can trip the card check.
  Review both kinds of error on your own data. [Honest limitations](#honest-limitations) lists the known ones.
- **It isn't a compliance certificate.** It's a technical control you can point
  to, and a record of what it replaced. What you claim to a regulator is still
  your call.

### The Sether family

The same engine runs in four places:

| Where | What |
| --- | --- |
| Your Python app | This package, `sether`: sync and async streaming, plus httpx, ASGI, WSGI, OpenAI and Anthropic integrations |
| Your TypeScript app | [`@raeven-co/sether` on npm](https://www.npmjs.com/package/@raeven-co/sether), the original engine this package ports 1:1 |
| Your browser | [Sether Shield for Chrome](https://chromewebstore.google.com/detail/keknopdmmjbljjjkmmpmkblldeapdjne): detection, masks and restore in AI chat boxes, all local. Decoys, watchlists and custom rules are in Pro. |
| Your editor | [Sether for VS Code](https://marketplace.visualstudio.com/items?itemName=GodfreyLebo.sether): scan, Copy Scrubbed, Paste with Originals Restored |
| Your agent's tool calls | [Gateway Guard](https://github.com/raeven-co/sether-gateway-guard) (beta, self-hosted): an OpenAI-compatible hop that refuses tool calls whose tokens weren't issued in that run |

The animation at the top shows Sether Shield. It's an illustration with fictional data.

---

## Install

```bash
pip install sether
```

Requires Python 3.9+. The phone detector uses [`phonenumbers`](https://pypi.org/project/phonenumbers/)
(installed automatically). Integration extras are optional:

```bash
pip install "sether[openai]"      # wrap_openai
pip install "sether[anthropic]"   # wrap_anthropic
pip install "sether[httpx]"       # wrap_httpx
pip install "sether[all]"         # all of the above
```

The ASGI and WSGI middlewares have no extra dependency.

---

## 60-second quickstart

```python
from sether import Sether

sether = Sether()

# Outgoing: redact before sending to the LLM.
safe = sether.redact_sync("my email is alice@example.com")
# -> "my email is <EMAIL_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>"

# Incoming: restore before showing the user.
back = sether.restore_sync(safe)
# -> "my email is alice@example.com"
```

The same `Sether` instance shares its vault between redaction and restoration,
which is how the round-trip identity is preserved.

> **Security: never call `restore_sync()` on serialized JSON** (tool-call
> arguments, JSON-mode replies, JSON response bodies). Restore is plain text
> substitution: an original value containing `"` or `\` can add keys to the
> document or break it. Use `restore_json` / `restore_json_value`, see
> [Never restore serialized JSON as text](#never-restore-serialized-json-as-text).

### Streaming (sync and async)

```python
sether = Sether()

# Synchronous: any iterable of text chunks.
def chunks():
    yield "Contact alice@"
    yield "example.com or call "
    yield "+1 415 555 2671."

redacted = "".join(sether.redact_stream(chunks()))
restored = "".join(sether.restore_stream([redacted]))

# Asynchronous: any async iterable (e.g. an LLM token stream).
async def run(llm_stream):
    async for piece in sether.aredact_stream(llm_stream):
        await forward_to_model(piece)
```

The redact stream holds back `safe_distance_bytes` (default 256) at the tail of
each chunk so a PII pattern crossing a chunk boundary is still detected when the
next chunk arrives. A long whitespace-free value (a JWT, an API key) is held
back up to `max(safe_distance_bytes * 4, 8192)` bytes so it is never emitted
partially across a boundary. For values larger than that bound, raise
`safe_distance_bytes` or use `redact_sync` on complete payloads. This round-trip
identity is verified by property-based tests over 60 random chunk partitions.

---

## Never restore serialized JSON as text

`restore_sync`, the restore streams and `sether.restore_sync()` are **plain
text substitution**: each original value is inserted exactly as it was,
unescaped. If the text is serialized JSON, such as LLM tool-call arguments, a
JSON-mode reply or a JSON response body, an original containing `"` or `\`
stops being data inside a string and becomes part of the document:

```python
# Tool-call arguments from the model reference a token...
args = '{"to": "<EMAIL_...>", "subject": "Hello <NAME_...>"}'
# ...whose original is:  Alice", "bcc": "attacker@example.com
json.loads(restore_sync(args, vault))
# -> {'to': 'bob@example.com', 'subject': 'Hello Alice', 'bcc': 'attacker@example.com'}
```

Built-in detectors can capture a trailing backslash (`password: hunter2\`),
which breaks the document the same way; custom detectors and vaults filled from
other systems can carry any character. Restore JSON value by value instead:

```python
from sether import restore_json, restore_json_value

# Serialized JSON in, serialized JSON out: each string value is restored and re-escaped.
safe_args = restore_json(tool_call.function.arguments, vault, strict=True)
# or, on the facade: sether.restore_json(tool_call.function.arguments, strict=True)

# Already parsed, e.g. an Anthropic tool_use block's `input`.
tool_input = restore_json_value(block.input, vault, strict=True)
```

- Object keys are never restored. Invalid JSON raises `json.JSONDecodeError`;
  there is no fallback to text replacement.
- One level at a time: a string value that itself holds serialized JSON is
  restored as plain text, so parse and restore it separately.
- `restore_json` re-serializes compactly; input formatting is not kept.
- `strict=True` (also accepted by `restore_sync`) raises `UnresolvedTokenError`
  when anything token-shaped would be left in place: an invented or expired
  token, a case-altered copy such as `<email_...>`, or a token in a key. Its
  `tokens` attribute lists them; restored originals are never included.
  Without `strict`, those pass through silently.
- Strict mode is not authorization. A model can still put a real token in the
  wrong field (the customer's address in `bcc`), so validate tool arguments
  before acting on them.
- `TOKEN_RE` is exported if you need to scan for tokens yourself.

**Sether's own restore paths restore JSON value by value.** They change only
the string values that hold a token and re-encode just those, so every other
byte is kept (formatting, key order, escapes and numbers). Object keys are
never restored.

- `sse_restore_iter` / `create_sse_restore_stream`: a `data:` payload that
  parses as JSON (OpenAI and Anthropic chunks) is restored value by value, so
  an original containing `"`, `\` or a line break can't change the JSON or
  break the SSE framing. Other payloads (`[DONE]`, plain text) are restored as
  text, and a line break in an original continues it on a new `data: ` line
  (the client receives it as `\n`). Each `data:` line is handled on its own, so
  a JSON payload split across several `data:` lines is restored as text.
- `wrap_httpx`, `SetherASGIMiddleware` and `SetherWSGIMiddleware`: an
  `event-stream` body is restored per `data:` payload as above. A body that
  parses as JSON is restored value by value, a JSON-typed body that doesn't
  (NDJSON, JSON Lines) line by line, and any other text body as text.
- `wrap_openai` / `wrap_anthropic`: when the request asks for JSON output
  (`response_format` `json_object` / `json_schema`, or Anthropic
  `output_config.format` / `output_format` with `json_schema`), the reply's
  content is restored value by value, and left tokenized if it isn't valid
  JSON. Streamed JSON-mode deltas are fragments of a document, so they stay
  tokenized: join them and call `restore_json`. Tool-call arguments stay
  tokenized by default. Pass `restore_tool_arguments=True` to restore
  non-streaming `tool_calls[].function.arguments` and `tool_use.input` value by
  value, and validate them before acting on them.

What is still restored as text:

- **JSON-mode output streamed over SSE.** `sse_restore_iter` (and the
  middlewares on an event-stream body) keeps each chunk valid, but the
  `delta.content` fragments join into a second JSON document the stream can't
  see, so an original lands in that document unescaped. Don't SSE-restore
  JSON-mode streams: collect the tokenized fragments and call `restore_json` on
  the assembled text.
- `restore_sync`, the restore streams and `sether.restore_sync()`, by design.
- `AliasVault.restore()` swaps decoys back by plain substitution too. On JSON,
  apply it to each parsed string value, never to the serialized document.

---

## Detectors

By default Sether runs the **basic pack**. Pass an explicit list to narrow scope,
or add the opt-in packs.

```python
from sether import Sether, basic_detectors, secrets_detectors, identity_detectors

sether = Sether(detectors=[*basic_detectors, *secrets_detectors, *identity_detectors])
```

### Basic pack (`basic_detectors`)

| Detector | Type | Method |
| --- | --- | --- |
| `email_detector` | `EMAIL` | RFC-5321-style regex. ASCII-only. |
| `phone_detector` | `PHONE` | `phonenumbers` (international format). For national-format numbers use `create_phone_detector(default_country="US")`. |
| `credit_card_detector` | `CC` | Bounded regex + Luhn check. |
| `ssn_detector` | `SSN` | Regex + SSA invalid-prefix rules. |
| `ipv4_detector` | `IPV4` | Strict octet-bounded regex. |
| `ipv6_detector` | `IPV6` | Candidate regex + in-tree validator. |
| `iban_detector` | `IBAN` | Regex + mod-97 checksum. |

### Secrets pack (`secrets_detectors`)

`aws_access_key_detector`, `openai_key_detector`, `anthropic_key_detector`,
`github_pat_detector` (classic + fine-grained), `slack_token_detector`,
`stripe_key_detector`, `jwt_detector`, `high_entropy_detector`
(Shannon entropy >= 3.5 bits/char).

### Identity pack (`identity_detectors`, opt-in)

Label-anchored detection for names, dates of birth, passport numbers, and
addresses. A value is redacted only when it appears with the label that
introduces it (`Name:`, `DOB:`, `Passport No:`, `Address:`) or, for a few
distinctive standalone shapes (a street line with a house number, a UK
postcode), a structure strong enough to keep false positives low. Labels are
recognised across many languages (Latin-script plus CJK, Cyrillic, Arabic), and
value capture is Unicode-aware.

Free-text NER (unlabelled names, organisations, locations in running prose) is
not covered here. The early NER package, [`@raeven-co/sether-ner`](https://www.npmjs.com/package/@raeven-co/sether-ner),
is TypeScript-only for now.

### Custom detectors

Anything with a `type` string and a `detect(text)` method works:

```python
import re
from sether import DetectorMatch

class OrderIdDetector:
    type = "ORDER_ID"
    _re = re.compile(r"\bORD-\d{8}\b")

    def detect(self, text):
        return [DetectorMatch(m.start(), m.end(), m.group(0)) for m in self._re.finditer(text)]
```

---

## Token vault

Tokens map back to originals through a vault. Sether ships an in-memory LRU
vault (10,000 entries, 1-hour TTL by default). Implement the `Vault` protocol to
change eviction, encrypt at rest, or namespace tokens per tenant.

```python
from sether import Vault   # a runtime-checkable Protocol: set/get/has/delete/size/clear

class NamespacedVault:
    def __init__(self, prefix):
        self._store = {}
        self._prefix = prefix
    def set(self, token, value): self._store[self._prefix + token] = value
    def get(self, token): return self._store.get(self._prefix + token)
    def has(self, token): return (self._prefix + token) in self._store
    def delete(self, token): return self._store.pop(self._prefix + token, None) is not None
    def size(self): return len(self._store)
    def clear(self): self._store.clear()

sether = Sether(vault=NamespacedVault("tenant-42:"))
```

The `Vault` interface is **synchronous**: restore substitutes tokens as bytes
flow through and cannot `await` a lookup per token. Front an async store (Redis,
Postgres) with a synchronous in-process cache you hydrate before the restore
pass, or keep the vault in-process.

---

## SSE / JSON-stream mode

OpenAI and Anthropic streaming responses come back as Server-Sent Events. The
SSE-aware stream redacts payloads inside `data:` lines while preserving the
`data:` / `event:` / `id:` / `retry:` framing and blank-line separators
verbatim.

```python
from sether import create_sse_redact_stream, basic_detectors, MemoryVault

vault = MemoryVault()
stream = create_sse_redact_stream(basic_detectors, vault)
out = stream.feed(sse_chunk) + stream.finish()
# or the iterator helpers: sse_redact_iter(chunks, detectors, vault)
```

---

## Drop-in integrations

```python
from sether import Sether
sether = Sether()
```

### httpx

```python
import httpx
from sether import wrap_httpx

client = wrap_httpx(httpx.Client(), detectors=sether.detectors, vault=sether.vault)
r = client.post("https://api.example.com/v1/chat",
                json={"q": "email alice@example.com"})
# The request carried <EMAIL_...>; r.text has any tokens the server echoed restored.
```

Works on `httpx.Client` and `httpx.AsyncClient`. Binary bodies pass through
untouched.

### ASGI (FastAPI / Starlette)

```python
from fastapi import FastAPI
from sether import SetherASGIMiddleware

app = FastAPI()
app.add_middleware(SetherASGIMiddleware, detectors=sether.detectors, vault=sether.vault)
```

### WSGI (Flask)

```python
from flask import Flask
from sether import SetherWSGIMiddleware

app = Flask(__name__)
app.wsgi_app = SetherWSGIMiddleware(app.wsgi_app, detectors=sether.detectors, vault=sether.vault)
```

### OpenAI SDK

```python
from openai import OpenAI
from sether import wrap_openai

client = wrap_openai(OpenAI(), detectors=sether.detectors, vault=sether.vault)
# Redacts messages out, restores choices back. Sync, async, and streaming clients.
```

### Anthropic SDK

```python
import anthropic
from sether import wrap_anthropic

client = wrap_anthropic(anthropic.Anthropic(), detectors=sether.detectors, vault=sether.vault)
# Redacts messages/system out, restores content blocks back.
```

The SDK wrappers are **structurally typed**. Sether never imports `openai` or
`anthropic`; any object matching the `chat.completions.create` /
`messages.create` shape works.

---

## Audit events

Each redaction can be described by a structured `AuditEvent` that maps to the
regulation it satisfies (GDPR Art. 28, SOC 2 CC6.7, HIPAA, PCI DSS, and more,
see `DEFAULT_REGULATION_MAPPINGS`). **The original value is never carried in an
event, only its length.** The JSON wire shape matches the TypeScript package
(camelCase keys) so events are interchangeable across both.

```python
from sether import AuditEvent, ConsoleAuditSink, MemoryAuditSink

sink = ConsoleAuditSink()   # JSONL to stderr; MemoryAuditSink accumulates for tests
sink.write(AuditEvent(timestamp="...", detector="EMAIL", value_length=17, token="<EMAIL_x>"))
```

---

## Honest limitations

These match the TypeScript package's documented limits:

- **Email detection is ASCII-only.** IDN/Unicode local parts do not match.
- **IPv6 `::1` (loopback) is not detected.** The candidate regex requires 4+
  chars. Loopback is not customer PII.
- **Credit-card regex is permissive**, then validated by Luhn. False positives
  in dense numeric content are possible.
- **Names / DOB / passport / address are label-anchored, not free-text NER.**
- **Very large whitespace-free values split across chunk boundaries** are held
  back only up to `max(safe_distance_bytes * 4, 8192)` bytes. Raise
  `safe_distance_bytes` or use `redact_sync` on complete payloads.
- **Restore is text substitution.** `restore_sync` and the restore streams
  insert originals unescaped. The SSE, httpx, ASGI, WSGI and SDK-wrapper paths
  restore JSON value by value, except JSON-mode output streamed over SSE. Use
  `restore_json` for your own JSON; see
  [Never restore serialized JSON as text](#never-restore-serialized-json-as-text).

---

## Parity with the TypeScript package

This port reproduces the TypeScript engine 1:1: the same detector
regexes (compiled with `re.ASCII` so `\b` / `\d` stay ASCII-only as in JS), the
same Luhn / mod-97 / SSA validation, the same overlap resolution (longest match
wins), the same `<TYPE_uuid>` token format, and the same safe-distance and
long-value streaming guards. 183 tests cover detectors, vault, streaming
(including a property-based chunk-partition round-trip), SSE, audit, and all
five integrations.

---

## License

MIT (c) Godfrey Lebo / Raeven Company LTD

## Reporting security issues

Email `emorylebo@gmail.com`. Do not file public issues for security findings.
