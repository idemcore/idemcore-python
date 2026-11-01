# Contributing

Thanks for your interest in `idemcore`.

This repository covers the Python **client** and the **local receipt verifier** only.
The Idemcore inference engine is not open source and is not part of this repository.

Welcome:

* Bug reports with a minimal reproduction (package version, Python version and OS, the
  call you made and what you expected).
* Fixes and tests for the client and the verifier.
* Documentation improvements.

Before opening a pull request:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v   # mocked API, no network
python -m pip install build twine && python -m build && twine check dist/*
```

Please keep runtime dependencies to `idemcore-verify` and `cryptography`, the HTTP layer
on the standard library, and compatibility with Python 3.9+.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
Questions about access, pilots or licensing: <https://idemcore.net>.
