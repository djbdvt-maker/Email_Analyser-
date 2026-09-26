# HopZero Qualification Registry & Specification Compiler

This directory contains the canonical security ontology source files, the domain-specific qualification compiler, the immutable compiled releases, and the cryptographic verification test suite for HopZero.

## Directory Structure

- `source/`: Human-authored canonical YAML specification:
  - `qualifications.yaml`: The 41 canonical qualification definitions, categories, strengths, allowed claim signatures, AI eligibility, and semantic validity requirements.
  - `floors.yaml`: The 6 critical floor predicates (`CF-01` through `CF-06`).
  - `scoring_buckets.yaml`: The 10 category scoring caps and maximum strength limits.
- `compiler/`:
  - `compile.py`: The domain-specific compiler and validator. Translates YAML source into a single machine-readable, deterministically serialized JSON snapshot and generates the matching `.sha256` integrity manifest.
- `releases/`:
  - `registry-v1.json`: The compiled, immutable specification snapshot for version `v1`.
  - `registry-v1.sha256`: The authoritative SHA-256 cryptographic digest matching the exact bytes of `registry-v1.json`.
- `hopzero_registry/`:
  - `loader.py`: The runtime loader that verifies SHA-256 integrity before parsing and caching the registry.
  - `models.py`: Immutable dataclasses representing qualifications, floors, and scoring buckets.
- `tests/`:
  - `test_compiler.py`: Comprehensive test suite verifying all 11 required compiler validation passes, determinism, SHA-256 integrity, and tamper detection.

## How to Compile

To compile the registry from source:

```powershell
python 01_REGISTRY/compiler/compile.py 01_REGISTRY/source 01_REGISTRY/releases
```

## Compiler Guarantees

1. **Deterministic Build**: Same source + same compiler version = same byte output.
2. **Clean Hash Design**: No circular self-hashes inside the JSON snapshot. The `.sha256` file matches the exact byte stream of `registry-v1.json`.
3. **Fail-Safe Startup**: Any modification to `registry-v1.json` without re-compilation triggers a `RegistryVerificationError` at runtime.
