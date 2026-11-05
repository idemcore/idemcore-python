# Changelog

## 0.3.0 (2026-11-05)

- Receipt verification accepts format **r2** as well as r1. r2 only renames three
  fields (`seed`→`variant`, `chain_fnv`→`chain_check`, `kernel_version`→`engine_version`);
  the signing domain and algorithm are unchanged. Existing r1 receipts still verify.
- The live API returns r2 receipts to this SDK (User-Agent 0.3.0). SDKs ≤0.2.x still
  receive r1.
- Trace replay compares aliased receipt fields across r1/r2.
- Interchangeable with the JavaScript SDK (`@idemcore/sdk` 0.3.0).

## 0.2.0 (2026-11-01)

- New `idemcore.trace`: reproducible agents. Record a whole agent run (model calls with
  their signed receipts, tool calls, approvals and other notes) as a hash-chained trace
  (`idemcore-trace/r1`), optionally signed with your own Ed25519 key.
- `verify_trace()` checks a trace offline: chain, step hashes, receipt signatures and
  commitments, and trace signatures (pin signers with `trusted_signers`).
- `replay()` re-sends the recorded model requests and checks that every answer is
  bit-identical (token ids, text, chain digest). With `agent=`, your agent code runs again
  and recorded tool results are fed back, so tools are never executed twice; any change
  in calls or arguments is reported as a divergence.
- CLI: `python -m idemcore trace verify|show|replay FILE` (also `idemcore-trace`).
- Traces are interchangeable with the JavaScript SDK (`@idemcore/sdk` 0.2.0).
- Docs: `docs/agent-replay.md`, example `examples/agent_replay.py`.

## 0.1.2 (2026-11-01)

- Source repository is now public. Package metadata lists Source, Issues, Documentation
  and Changelog links.
- Added SECURITY.md and CONTRIBUTING.md.
- No code changes.

## 0.1.1 (2026-11-01)

- README: the quickstart, streaming and async examples now pass `model` explicitly
  (read from `client.models()`), since the API requires a model id.
- Release published from GitHub Actions with PyPI Trusted Publishing.

## 0.1.0 (2026-11-01)

- First release: sync and async clients, streaming, signed receipts and local
  receipt verification.
