# Sether (Python)

> **Hide personal data from your AI before it reaches any LLM provider.**
>
> Named for the Hebrew *sether* (סֵתֶר), *the hiding place*. Psalm 32:7.

![Sether redacts PII locally before it reaches the LLM: the input "Hi, this is Amara Okafor — my account email is amara.okafor@acme.com … card 4242 4242 4242 4242 … call me at +1 (415) 555-2671 … SSN 123-45-6789" becomes "Hi, this is &lt;NAME&gt; — my account email is &lt;EMAIL&gt; … card &lt;CC&gt; … &lt;PHONE&gt; … &lt;SSN&gt;". The token vault stays in your infrastructure and restore() swaps the originals back into the reply.](https://raw.githubusercontent.com/raeven-co/sether/main/assets/sether-redaction.png)

*Your app → **Sether** redacts locally → LLM. The token vault stays in your infrastructure; `restore_sync()` swaps the originals back into the reply.*

Sether is a streaming PII-redaction layer that sits between your application
and any LLM API. It detects sensitive data (email, phone, SSN, credit card,
IBAN, IP addresses, secrets, and labelled identity fields), swaps each match
for a stable token before the request leaves your boundary, then restores the
original values transparently in the response.

This is the Python port of [`@raeven-co/sether`](https://www.npmjs.com/package/@raeven-co/sether).
Same detection engine, same token format, same chunk-boundary streaming safety,
ported faithfully to Python with both synchronous and asynchronous streaming and
drop-in integrations for **httpx, ASGI (FastAPI / Starlette), WSGI (Flask),
the OpenAI SDK, and the Anthropic SDK**.

A product of **Raeven Company LTD**.

---

## Why this exists

If your application sends a customer's email, phone number, or any other PII to
an LLM provider, that is a sub-processor disclosure under GDPR Article 28.
Credit-card data pulls you into PCI DSS scope. Health identifiers trigger HIPAA.
Sether stops the leak at the boundary: sensitive substrings become stable tokens
before the bytes leave your process, and `restore()` swaps them back so your
application code does not need to branch on redacted text.

**This package does not phone home.** Streams are not sent to Raeven. The vault
stays in your process (or your own backing store if you implement `Vault`).

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
not covered here; that is the separate `sether-ner` roadmap item.

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

---

## Parity with the TypeScript package

This port reproduces the audited TypeScript engine 1:1: the same detector
regexes (compiled with `re.ASCII` so `\b` / `\d` stay ASCII-only as in JS), the
same Luhn / mod-97 / SSA validation, the same overlap resolution (longest match
wins), the same `<TYPE_uuid>` token format, and the same safe-distance and
long-value streaming guards. 76 tests cover detectors, vault, streaming
(including a property-based chunk-partition round-trip), SSE, audit, and all
five integrations.

---

## License

MIT (c) Godfrey Lebo / Raeven Company LTD

## Reporting security issues

Email `emorylebo@gmail.com`. Do not file public issues for security findings.
