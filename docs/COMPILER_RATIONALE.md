# What Do We Gain From Our Own Qualification Compiler?

## Executive Overview

In email forensic security systems, a common failure mode is **semantic drift**: different developers, analyzer modules, heuristics, or AI components hardcode slightly diverging names, strengths, point caps, and threat definitions. Over time, rules become inconsistent, AI hallucinates non-existent detection categories, and historical investigation reports lose audit reproducibility.

HopZero solves this definitively by implementing its own **domain-specific security specification compiler** (`01_REGISTRY/compiler/compile.py`).

The HopZero compiler is **not** a general programming language compiler; it is a **rigorous specification compiler** that translates human-authored security ontology source files into an immutable, mathematically verified, machine-readable release snapshot.

---

## The Compiler Architecture

```
Human-Authored Security Specification
  ├─ 01_REGISTRY/source/qualifications.yaml    (41 signal qualifications)
  ├─ 01_REGISTRY/source/floors.yaml            (6 critical floors CF-01 to CF-06)
  └─ 01_REGISTRY/source/scoring_buckets.yaml   (10 category caps & limits)
                       │
                       ▼
          [ HopZero Registry Compiler ]
     Deterministic Validation Pipeline (A - L)
     - Qualification uniqueness & schema
     - Strength ordering (Negligible < Weak < Moderate < Strong)
     - Producer authorization (deterministic, ai_reasoner)
     - AI-eligibility invariant & disqualifiers
     - Claim signature syntax & uniqueness
     - Floor rule syntax & cross-references
     - Category & scoring bucket point caps
                       │
                       ▼
         [ Canonical Release Snapshot ]
     registry-<version>.json (deterministic sorted bytes)
     registry-<version>.sha256 (exact cryptographic digest)
                       │
                       ▼
          [ Runtime Integrity Loader ]
     hopzero_registry.loader (verifies SHA-256 before loading)
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
 Forensics & Evidence Normalizer   Backend Engine
 (Hop-0 routing, auth, links,     (Finding validation, AI trust boundary,
  domain, attachments, identity)   floor engine, score engine)
```

---

## 12 Defensible Architectural Advantages

### 1. Single Canonical Vocabulary
The compiler creates **exactly one source of truth** for every qualification code (`CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE`, `PROTECTED_BRAND_LOOKALIKE_DOMAIN`, etc.), its category, and allowed claim signatures. There are zero shadow registries or duplicate dictionaries.

### 2. Elimination of Semantic Drift Between Developers
Engineers cannot invent custom or misspelled qualification names (e.g. `LOOKALIKE_DOMAIN` vs `PROTECTED_BRAND_LOOKALIKE_DOMAIN`) in individual analyzers. The compiler rejects unauthorized codes at build time, and the static drift test suite audits analyzers against the compiled release.

### 3. Static Cross-Reference Validation
The compiler ensures that every qualification code referenced in floor requirements (`floors.yaml`) actually exists in `qualifications.yaml`. A typo in a floor predicate fails compilation immediately before any code reaches production.

### 4. Strict AI Eligibility & Trust Boundary Governance
AI models must never propose qualifications that require deterministic proof (such as SPF/DKIM authentication failures or raw routing fabrications). The compiler statically verifies that:
- Qualifications marked `ai_eligible: true` explicitly allow `ai_reasoner` and provide non-empty `validity_requirements` with negative disqualifier phrases.
- Non-AI-eligible qualifications **strictly disallow** `ai_reasoner` as a producer.

### 5. Floor Rule Integrity
HopZero enforces six non-negotiable critical floors (`CF-01` through `CF-06`). The compiler validates the operator (`AND`, `OR`), minimum required strengths, target severity (`High`), and constituent qualification dependencies for each floor.

### 6. Scoring Cap & Category Governance
The compiler validates the point caps (e.g., 30 points max for Routing fabrication, 18 for Infrastructure) and maximum strengths across all 10 forensic categories. Every qualification must belong to an explicitly defined scoring bucket.

### 7. Strict Semantic Structural Consistency
Contradictions—such as a `default_strength` exceeding `maximum_strength`, an invalid floor operator (e.g., `XOR`), or duplicate claim signatures—are caught and rejected by compiler passes before release generation.

### 8. Byte-for-Byte Deterministic Compilation
The compilation process is 100% deterministic. Using sorted keys, uniform indentation, and reproducible build timestamping (`SOURCE_DATE_EPOCH` / source mtime), compiling the same source specifications with the same compiler version **always yields the exact same byte sequence**.

### 9. Cryptographic Release Integrity (Clean SHA-256 Design)
The release artifact (`registry-v1.json`) is free from self-referential hash paradoxes. The external `.sha256` manifest contains the precise cryptographic SHA-256 digest of the entire JSON release byte stream.

### 10. Tamper-Evident Runtime Verification
The runtime loader (`hopzero_registry.loader.load_registry`) computes the SHA-256 digest of the release file upon startup and compares it against the `.sha256` file. Any runtime tampering or bit corruption immediately raises a `RegistryVerificationError` and prevents startup.

### 11. Known Semantic Baseline for Historical Auditing
Every investigation records the `qualification_registry_version` (e.g., `v1`). Because releases are immutable and version-controlled, an investigation conducted today can be accurately re-evaluated and audited years later against the exact semantic rules in force when it was executed.

### 12. Defense in Depth: Compiler Validation vs. Runtime Validation
Compiler validation validates the **specification structure and consistency**. Runtime validation validates the **observed evidence and data grounding**. The compiler does not inspect emails, and runtime validation does not guess specifications—they form two complementary, non-overlapping security boundaries.
