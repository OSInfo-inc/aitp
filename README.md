# AI Trust Protocol (AITP)

**An open standard for trust, verification, and accountability in autonomous agent systems.**

Version 0.1 (Draft) | March 2026

Authors: Michael Harrison and Ard Haskell, OSInfo Inc.

---

## The Problem

AI agent systems operate without cryptographic identity, audit trails, or scoped permissions. Every deployment is a trust-me architecture. AITP provides the trust layer the industry forgot to build.

## What AITP Is

AITP is a specification for process integrity and nonrepudiation in AI systems. It defines:

- **Six Trust Primitives**: Agent Identity, Scope Binding, Attestation, Co-signature Protocol, Signing Authority, Revocation
- **Three Operational Tiers**: Crawl (read-only), Analysis (draft), Action (publish, requires co-signature)
- **DDA (Distributed Deterministic Attestation)**: A scalable verification architecture for validating AI output across millions of artifacts using sharded agents, boundary overlap, and cross-architecture validation
- **Resilience Requirements**: Hybrid cloud/local/offline architecture with mandatory air-gapped validation nodes
- **AITP Top 10**: The ten most critical trust risks in agent systems, modeled after the OWASP Top 10

## What AITP Is NOT

AITP does not guarantee output correctness. It guarantees that every action is attributed, signed, scoped, and auditable. Due process, not a stamp of truth.

## Documents

| Document | Description |
|----------|-------------|
| [AITP Specification](spec/AITP-Specification.md) | The full technical specification |
| [AITP Top 10](spec/AITP-Top-10.md) | Ten critical trust risks in agent systems |
| [OWASP Agentic Crosswalk](spec/AITP-Agentic-Top10-Crosswalk.md) | Mapping AITP to OWASP Top 10 for Agentic Applications |

## Key Concepts

### Trust Primitives
Every agent holds an Ed25519 key pair. Every action produces a signed attestation. Consequential actions require co-signature from an architecturally independent entity. Compromised agents are revoked immediately with bounded blast radius.

### DDA: Distributed Deterministic Attestation
Humans cannot validate a million AI decisions. But a human can validate the system that validates those decisions. DDA shards validation across agent tiers, with each tier operating on different data types using different model architectures. Volume cascades from millions of artifacts down to single-digit human decision points.

### Resilience
Any trust standard that depends on a single provider is not a trust standard. AITP requires hybrid architecture: cloud for speed, local for continuity, offline for trust-critical validation.

## License

This work is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

## Contact

- Michael Harrison: michael.harrison@osinfo.com
- Ard Haskell: ard.haskell@osinfo.com
- OSInfo Inc.: https://osinfo.com
