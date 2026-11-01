# idemcore (Python SDK)

Python client for the [Idemcore](https://idemcore.net) API. Every chat answer comes
with a signed receipt, and this package can check that receipt on your own machine.

* Chat completions (plain or streaming) that return the answer text **and** its receipt id.
* Fetch a receipt and its public token log.
* Verify receipts locally: Ed25519 signature (L1), token-log chain (L2), and your
  prompt / answer against the receipt's salted commitments (disclosure).
* Server-side checks: remote verify, replay on an independent build (L3), audit export.
* Sync and asyncio clients. Python 3.9+. Dependencies: `idemcore-verify` and `cryptography`.

Decoding is greedy: **temperature is fixed at 0** (and `n` at 1). Sending any other
temperature raises `InvalidRequestError` before a request is made.

## Install

```sh
pip install idemcore
```

## Get an API key

1. Sign in to the console at <https://console.idemcore.net/#/login> (the public
   preview is free, with preview limits).
2. Create an API key. It starts with `ick_` and is shown only once.
3. Export it:

```sh
export IDEMCORE_API_KEY="ick_..."
```

The client reads `IDEMCORE_API_KEY` (and, optionally, `IDEMCORE_BASE_URL`, default
`https://api.idemcore.net`). You can also pass `Idemcore(api_key=...)`.

## Quickstart

```python
from idemcore import Idemcore

client = Idemcore()
model = client.models()[0]["id"]   # pass a model id explicitly

r = client.chat("Name the three primary colours.", model=model, max_tokens=64)
print(r.text)
print(r.receipt_id)          # rcpt_...

# Verify on this machine: signature, token-log chain, and that the receipt
# commits to exactly this prompt and this answer.
result = client.verify_local(r)
print(result.ok)             # True
for name, level in result.levels.items():
    print(name, level.ok, level.errors)
```

`r.receipt` is the full signed receipt, `r.salt` the base64url salt of a
`hash_only` receipt (the default privacy mode). Anyone with the salt and the text
can check the commitments, so keep the salt with the conversation.

### Streaming

```python
with client.chat_stream("Write a haiku about receipts.", model=model) as stream:
    for chunk in stream:
        print(chunk.delta, end="", flush=True)

print()
print(stream.result.receipt_id)   # the receipt arrives with the last chunk
```

### Async

```python
import asyncio
from idemcore import AsyncIdemcore

async def main():
    client = AsyncIdemcore()
    model = (await client.models())[0]["id"]
    r = await client.chat("Hello", model=model)
    print(r.text, r.receipt_id)

asyncio.run(main())
```

### Receipts, logs and server-side checks

```python
receipt = client.get_receipt("rcpt_...")             # GET /v1/receipts/{id}
log = client.get_receipt_log("rcpt_...")             # GET /v1/receipts/{id}/log
print(log.log_format)                                # idemcore-log/r1-public

client.verify_remote(r.receipt, messages=r.messages, salt=r.salt,
                     output_token_ids=r.output_token_ids)   # POST /v1/receipts/verify
client.replay_result(r)                              # POST /v1/receipts/replay (L3)
lines = client.audit_export("2026-10-01", "2026-10-31")     # POST /v1/audit/export (NDJSON lines)
client.models()                                      # GET /v1/models
client.keys()                                        # GET /v1/keys (signing keys, JWKS)
```

### Offline verification without the client

```python
from idemcore.verify import verify_receipt

res = verify_receipt(receipt, log_text=log_text,
                     messages=messages, salt=salt, output_token_ids=output_ids)
```

The production receipt-signing public key is bundled
(`idemcore.verify.DEFAULT_TRUSTED_KEYS`); pass `keys=client.keys()` to use the live
key set instead.

## Errors

All errors derive from `idemcore.IdemcoreError` and carry `status`, `type` and
`message`: `AuthenticationError` (401), `PermissionDeniedError` (403, key lacks a
scope), `NotFoundError` (404), `ConflictError` (409), `InvalidRequestError` (400/415), `RateLimitError`
(429, see `.retry_after`), `InsufficientQuotaError` (429), `ServiceUnavailableError`
(503), `InternalServerError` (5xx), `APIConnectionError` (network). GET requests are
retried on 429/503 (`max_retries`, default 2); chat requests are never retried
automatically, so a retry never creates a second receipt behind your back.

## Using the OpenAI SDK instead

The API is OpenAI-compatible, so `openai.OpenAI(base_url="https://api.idemcore.net/v1",
api_key=...)` also works; the receipt is in the response's `idemcore_receipt` field.
This package adds typed receipts and local verification.

## Development

```sh
pip install -e .
python -m unittest discover -s tests          # mocked API, no network
IDEMCORE_LIVE=1 python -m unittest tests.test_client.LiveSmoke   # GET /health only
```

## License

Apache-2.0
