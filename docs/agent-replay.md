# Reproducible agents: record, replay, verify

An agent run is a sequence of model calls and tool calls. Idemcore already signs
a receipt for every model answer. A **trace** chains those receipts together with
your tool calls, so you can later prove what the agent saw and did, and run it
again and get the same answers token for token.

| | What it does | Network |
|---|---|---|
| `Session` / `record()` | Records model calls (with their receipts) and tool calls into a hash-chained trace | API calls you make anyway |
| `verify_trace()` | Checks the chain, every hash, every receipt signature and commitment, and your own signature | **none** |
| `replay()` | Sends the recorded model requests again, checks that the output tokens are bit-identical, and feeds recorded tool results back to your agent | one API call per model step |

## Record

```python
import idemcore
from idemcore import trace

client = idemcore.Idemcore()          # IDEMCORE_API_KEY from the environment

def get_weather(city):
    return {"city": city, "temp_c": 18}

def agent(s):
    city = s.chat("Which city is the Eiffel Tower in? One word.", max_tokens=8).text.strip(" .")
    w = s.tool("get_weather", {"city": city}, get_weather)       # runs the tool, records args + result
    return s.chat(f"Weather: {w}. One-sentence forecast.", max_tokens=40).text

s = trace.Session(client, meta={"job": "forecast-demo"})
agent(s)
s.save("run.trace.json")
```

* `s.chat(...)` takes the same arguments as `client.chat(...)`.
* `s.tool(name, args, fn)` calls `fn(**args)` (or `fn(args)` when `args` is not a dict). Exceptions are recorded and re-raised.
* `s.record_tool(name, args, result)` records a tool you ran yourself (for example a function call the model asked for).
* `s.record_model(result, max_tokens=...)` records a streamed answer: `s.record_model(client.chat_stream(...).until_done(), ...)`.
* `s.note("approval", {...})` adds a free-form step, such as a human sign-off.
* Tool arguments and results must be JSON (numbers, strings, lists, objects). Arguments are stored as canonical JSON text (sorted keys); results keep the key order the tool returned, so a replayed agent sees exactly the same object.

### Signing

```python
key = trace.generate_signing_key()     # private JWK; store it like any secret
s.save("run.trace.json", sign_with=key)
print(key["kid"])                       # publish this id so others can pin it
```

The trace stores the public key and the signature, never the private part.

## Verify (offline)

```bash
python -m idemcore trace verify run.trace.json --signer ed25519:1a2b3c4d5e6f7a8b
python -m idemcore trace show run.trace.json
```

```python
res = trace.verify_trace(trace.load_trace("run.trace.json"), trusted_signers=["ed25519:..."])
assert res.ok, res.errors
```

`verify_trace` fails if any step was edited, removed, inserted or reordered, if
the manifest was changed, if a receipt signature is not from a trusted Idemcore
key, or if the recorded prompt, output tokens or text do not match the receipt's
commitments. It needs no network. Pass `keys=` to use a key set fetched from
`GET /v1/keys` instead of the bundled keys.

## Replay

```bash
python -m idemcore trace replay run.trace.json          # model calls only
```

```python
report = trace.replay(trace.load_trace("run.trace.json"), client, agent=agent)
print(report.summary())     # OK: 2/2 model steps bit-identical, 1 tool/note steps fed from the trace
```

* **Model-only replay** (no `agent=`): every recorded request is sent again in order; the answer's token ids, text, chain digest, token counts, model and weights hash must match.
* **Agent replay** (`agent=fn`): your agent code runs again with a `ReplaySession`. Model calls go to the API and are checked. Tool calls return the recorded result and **do not run the tool**, so a replay is safe even for tools with side effects (payments, emails, writes) and gives the same input even when the outside world has changed. If the agent makes a different call, in a different order or with different arguments, replay stops and reports where.
* `strict=True` stops at the first different answer.
* A change of `engine_build` is reported as a note, not a failure: the answer must still be bit-identical.
* `report.replay_trace` is a new trace of the replay itself (its `meta_json` names the original session), so a replay is auditable too.

## What a trace proves, and what it does not

* It proves that each model answer was produced by Idemcore for exactly that request (signed receipt), and that the sequence of steps has not been edited since it was recorded (hash chain, optional signature).
* Tool results are what **your code** recorded. The trace shows they were not changed afterwards; it cannot prove that the tool returned them. Sign traces at the source and keep the tool's own logs if that matters.
* A trace contains your prompts, answers and the salts that open `hash_only` receipts. Store it like the conversation itself.

## Trace format (`idemcore-trace/r1`)

```jsonc
{
  "manifest": {
    "format": "idemcore-trace/r1", "session_id": "ses_<24 hex>", "created_at": "2026-11-01T14:30:00.000Z",
    "sdk": "idemcore-python/0.1.x", "meta_json": "{\"job\":\"forecast-demo\"}",
    "genesis": "<hex>", "head": "<hex of last step>", "step_count": 3
  },
  "manifest_hash": "<hex>",
  "steps": [
    {"index": 0, "type": "model", "prev": "<genesis>", "body": {
       "request": {"messages": [...], "model": null, "max_tokens": 8, "privacy": null}, "request_hash": "...",
       "receipt_id": "rcpt_...", "receipt": {...}, "receipt_hash": "...", "salt": "...",
       "output_token_ids": [...], "output_text": "Paris", "output_text_sha": "...",
       "finish_reason": "stop", "usage": {...}, "streamed": false}, "hash": "..."},
    {"index": 1, "type": "tool", "prev": "...", "body": {
       "name": "get_weather", "call_id": "call_1", "args_json": "{\"city\":\"Paris\"}", "args_hash": "...",
       "result_json": "{\"city\":\"Paris\",\"temp_c\":18}", "result_hash": "...", "error": null}, "hash": "..."}
  ],
  "signatures": [{"alg": "Ed25519", "kid": "ed25519:<16 hex>", "x": "<base64url public key>", "signature": "<base64url>"}]
}
```

Hashes are SHA-256 with domain separation, `H(tag, parts…) = sha256("idemcore/<tag>/r1" 0x00 ‖ (len64le(part) ‖ part)…)`, the same construction as receipts:

| Field | Value |
|---|---|
| `genesis` | `H("trace-genesis", session_id)` |
| step `hash` | `H("trace-step", canonical(step without hash))` |
| `manifest_hash` | `H("trace-manifest", canonical(manifest))` |
| `request_hash` | `H("trace-request", canonical(request))` |
| `receipt_hash` | `H("trace-receipt", canonical(receipt))` |
| `output_text_sha` | `H("trace-text", utf8(output_text))` |
| `args_hash` / `result_hash` | `H("trace-tool-args", args_json)` / `H("trace-tool-result", result_json or "")` |
| signature | Ed25519 over `"idemcore-trace/r1\n" ‖ manifest_hash` |

`canonical` is the receipts' canonical JSON (sorted keys, no whitespace, UTF-8, integers only). Tool data, which may contain decimals, is kept as compact JSON text (arguments and notes with sorted keys, results in the tool's key order) and hashed as bytes, so traces verify identically in Python and JavaScript. When replaying a trace recorded by the other SDK, tool arguments are compared by value (`1e-07` and `1e-7` are equal).
