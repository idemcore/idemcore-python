# Security policy

## Scope

This repository contains `idemcore`, the Python client for the Idemcore API and its
local receipt verifier. Please report privately:

* a way to make `verify_receipt` / `verify_local` accept a receipt whose signature, token
  log or disclosure commitments do not match;
* a way for the client to send an API key anywhere other than the configured base URL;
* a crash, hang or excessive resource use caused by a crafted receipt, log or API response;
* a weakness in how the package is built or published.

Problems with the hosted API or the console (`api.idemcore.net`, `console.idemcore.net`)
are also welcome at the same address.

## How to report

Email **security@idemcore.net** with the subject `SECURITY: idemcore-python`, or use
GitHub's private vulnerability reporting ("Report a vulnerability" on the Security tab).
Include the package version, a minimal reproduction and the Python version and OS you
used.

We aim to acknowledge reports within 3 working days and to agree a disclosure date with
you. Please do not open a public issue for a security report.

## Supported versions

Only the latest release receives fixes. Releases are published to PyPI from GitHub
Actions with Trusted Publishing and carry PEP 740 attestations that link each file to
the commit and workflow run that built it.
