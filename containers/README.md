# Pinned build environments

Verification layers L3 (build + test) and L4 (conformance) run inside pinned
containers so that verdicts do not depend on the host machine's toolchain.

| Image | Provides |
|---|---|
| `build-jdk24/` | JDK 24 (native ML-KEM/ML-DSA), Maven and Gradle |
| `build-python/` | Python toolchain for the Tier-2 Python application |
| `crypto-tools/` | OpenSSL ≥ 3.5, liboqs, and CLI utilities for cross-provider checks |

Images are referenced by digest, not by tag. The Dockerfiles are part of the
released artifact; rebuilding them from scratch is part of the reproduction
path. These images are not yet built — see `docs/STATUS.md` and ADR-002 for
the interim single-file compile used by L3.
