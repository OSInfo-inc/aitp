# AITP / OWASP Top 10 for Agentic Applications Crosswalk

**Version:** 1.1
**Date:** March 2026
**Authors:** Michael Harrison, Ard Haskell, OSInfo Inc.
**License:** CC BY-SA 4.0

---

## Purpose

This document maps each risk in the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) to the specific AITP mechanisms that mitigate it. The OWASP Agentic Top 10 identifies the security risks. AITP provides the trust architecture that addresses them.

The mapping demonstrates that AITP's six trust primitives (Agent Identity, Scope Binding, Attestation, Co-signature Protocol, Signing Authority, and Revocation), three operational tiers, and Distributed Deterministic Attestation framework provide comprehensive coverage of the OWASP Agentic risk landscape.

---

## Crosswalk Summary

| OWASP Agentic Risk | AITP Primary Mitigation | AITP Sections |
|---|---|---|
| ASI01: Agent Goal Hijack | Operational Tiers + Quarantine Architecture | 2.1, 4.1, 4.2, 5.2 |
| ASI02: Tool Misuse and Exploitation | Scope Binding + Signing Authority | 3.2, 3.5, 4.3 |
| ASI03: Identity and Privilege Abuse | Agent Identity + Scope Binding + Revocation | 3.1, 3.2, 3.6 |
| ASI04: Agentic Supply Chain Vulnerabilities | Attestation + Scope Binding + Co-signature | 2.3, 3.2, 3.3, 3.4 |
| ASI05: Unexpected Code Execution | Scope Binding + Operational Tiers + Co-signature | 3.2, 4.3, 5.1, 5.2 |
| ASI06: Memory and Context Poisoning | Operational Tiers + Quarantine + Cross-Architecture | 2.6, 4.1, 4.2, 4.4 |
| ASI07: Insecure Inter-Agent Communication | Agent Identity + Attestation + Co-signature | 3.1, 3.3, 3.4, 5.1 |
| ASI08: Cascading Failures | Operational Tiers + Revocation + DDA | 2.5, 3.6, 4.4, 6.4 |
| ASI09: Human-Agent Trust Exploitation | Co-signature Protocol + Attestation | 3.3, 5.1, 5.2 |
| ASI10: Rogue Agents | Agent Identity + Revocation + Attestation | 2.2, 3.1, 3.3, 3.6 |

---

## Detailed Mapping

### ASI01: Agent Goal Hijack

**OWASP Risk Description:**
Attackers alter an agent's objectives through malicious text injected via external data sources. Agents often cannot reliably separate instructions from data, leading to unintended actions such as data exfiltration, unauthorized tool invocation, or goal redirection.

**AITP Mitigation:**

AITP does not claim to prevent prompt injection at the model level. No current architecture can. Instead, AITP contains the blast radius of a successfully hijacked agent through layered architectural controls.

- **Tier separation (Section 4).** External data enters the system only through Tier 1 agents, which are read-only and write exclusively to a quarantine buffer. A hijacked Tier 1 agent can corrupt data in quarantine but cannot take any action on external systems. The quarantine buffer is the containment boundary.

- **Quarantine scanning (Section 5.2).** Data promoted from quarantine to Tier 2 passes through a deterministic rules engine (not an LLM) that checks for structural anomalies, known injection patterns, and format compliance. This is not a guarantee against injection, but it is a non-LLM gate that is immune to the injection techniques that target language models.

- **Cross-architecture review (Section 4.2).** Tier 2 agents MUST operate on different models and architectures than Tier 1. A goal hijack payload crafted for a specific model's behavior is less effective against a different model at the next tier.

- **Co-signature for action (Section 5.2).** Even if a Tier 2 agent is hijacked through a sophisticated multi-step injection, its output cannot reach Tier 3 (real-world execution) without co-signature from an independent agent of different architecture or an orchestrator.

**AITP Trust Risk Parallel:** ATR-07 (Poisonable Context Windows).

---

### ASI02: Tool Misuse and Exploitation

**OWASP Risk Description:**
Agents misuse legitimate tools due to ambiguous prompts, manipulated input, or overprivileged tool access. A tool designed for one purpose is invoked for a different, potentially destructive purpose. The tools are legitimate; their invocation is not.

**AITP Mitigation:**

- **Scope Binding (Section 3.2).** Every agent is bound to a permission manifest that enumerates permitted operations at the resource level. An agent authorized for "execute:tool/search" cannot invoke "execute:tool/deploy". There is no wildcard. There is no implicit capability inheritance from the tool's full feature set. The Signing Authority (Section 3.5) enforces scope at signing time: if the proposed action is not in the manifest, the signing request is rejected.

- **Tier constraints (Section 4).** Tier 1 agents have no tool execution permissions beyond read operations. Tier 2 agents may invoke analysis tools but cannot execute actions that modify external state. Only Tier 3 agents can invoke tools that affect the real world, and every such invocation requires co-signature.

- **Co-signature for destructive tool use (Section 5.2).** Destructive operations require orchestrator co-signature. The orchestrator verifies that the tool invocation falls within the agent's scope manifest and that the attestation chain supports the action. The orchestrator does not evaluate whether the tool use is wise; it evaluates whether it is authorized and procedurally sound.

**AITP Trust Risk Parallel:** ATR-03 (Unscoped Tool Permissions).

---

### ASI03: Identity and Privilege Abuse

**OWASP Risk Description:**
Agents inherit high-privilege credentials and sessions that can be unintentionally reused or escalated across systems without proper scoping. Agent identity is conflated with credential access, and privilege boundaries are porous.

**AITP Mitigation:**

- **Cryptographic Agent Identity (Section 3.1).** Every agent instance holds its own Ed25519 key pair. Identity is the public key, not a name, role, or shared credential. Two agents using the same model are two different identities. Identity is bound to a single instance and does not transfer.

- **Scope Binding (Section 3.2).** Permissions are explicit, per-resource, and signed by the Signing Authority. An agent's scope is its manifest, not the union of credentials it can access. "read:database/customers" does not imply "read:database/financials", even if the underlying database credential permits both. Scope enforcement happens at the Signing Authority level, not at the tool level.

- **No implicit trust inheritance (ATR-05).** Child agents receive their own identity and their own scope manifest. A parent agent's permissions are not inherited. A parent's revocation does not automatically cascade to children, but the lineage is traceable through the attestation chain.

- **Revocation (Section 3.6).** When privilege abuse is detected, the abusing agent's identity is revoked immediately. The revocation is granular: one agent, one key, one scope. Other agents in the system are unaffected.

**AITP Trust Risk Parallel:** ATR-04 (No Cryptographic Identity), ATR-05 (Implicit Trust Inheritance).

---

### ASI04: Agentic Supply Chain Vulnerabilities

**OWASP Risk Description:**
Dynamically fetched components such as tools, plugins, and MCP servers can be compromised, altering agent behavior or exposing sensitive data. The agent faithfully executes a compromised component with its own credentials.

**AITP Mitigation:**

- **Attestation for tool provenance (Section 3.3).** Every tool invocation produces a signed attestation record. The record includes the tool identifier, the input hash, the output hash, and the invoking agent's identity. If a compromised tool produces anomalous output, the attestation chain identifies exactly which tool, invoked by which agent, at which time, produced the suspicious output.

- **Scope Binding limits blast radius (Section 3.2).** A compromised tool operates within the invoking agent's scope, and that scope is bound by the permission manifest. If the agent's manifest permits "execute:tool/search" with "read:database/customers", the compromised tool cannot access resources outside that scope, regardless of what the tool's code attempts.

- **Co-signature as supply chain checkpoint (Section 3.4).** Consequential actions produced through tool execution still require co-signature. A compromised tool that generates a destructive action must still pass the co-signature gate. The co-signer (a different agent on a different architecture) independently evaluates the proposed action, providing a second check that the tool's output is not malicious.

- **Revocation for compromised tool chains (Section 3.6).** If a tool is determined to be compromised, every agent that invoked the tool during the compromise window is identifiable through the attestation chain. These agents can be audited, and their tool-dependent actions can be reviewed or rolled back.

**AITP Trust Risk Parallel:** ATR-03 (Unscoped Tool Permissions), ATR-08 (Unverified External Data Ingestion).

---

### ASI05: Unexpected Code Execution

**OWASP Risk Description:**
Agents generate or execute code unsafely, including shell commands and scripts that bypass validation or review processes. Code generation is treated as text generation, with no distinction between safe and unsafe execution contexts.

**AITP Mitigation:**

- **Scope Binding (Section 3.2).** Code execution is an execute permission that must be explicitly listed in the agent's scope manifest with specific resource targets. "execute:tool/python-sandbox" is a different permission from "execute:tool/shell". An agent without execute permissions in its manifest cannot execute code at all, regardless of what it generates.

- **Tier 3 co-signature requirement (Section 4.3, Section 5.2).** Code execution that modifies production state is a Tier 3 action requiring co-signature. The co-signing agent reviews the proposed execution for safety. Destructive code execution (modifying infrastructure, deleting resources) requires orchestrator co-signature. The Signing Authority will not issue a co-signature token for an execute action without the appropriate co-signature for the action's consequence class.

- **Attestation of execution (Section 3.3).** Every code execution produces a signed attestation record containing the input hash (the code to be executed), the output hash (the execution result), and the executing agent's identity. This creates a verifiable audit trail of what code was executed, by which agent, with what result.

- **Tier separation prevents direct execution from ingestion (Section 4.4).** Code retrieved from external sources enters at Tier 1 (quarantine). It cannot be executed until it has been promoted through Tier 2 (analysis and review) to Tier 3 (action), with co-signature at the Tier 2 to Tier 3 boundary. There is no fast path from ingestion to execution.

**AITP Trust Risk Parallel:** ATR-03 (Unscoped Tool Permissions), ATR-01 (Unsigned Agent Actions).

---

### ASI06: Memory and Context Poisoning

**OWASP Risk Description:**
Attackers poison memory systems, RAG databases, and embeddings to influence future agent decisions across sessions. Unlike direct prompt injection, memory poisoning persists and affects multiple future interactions.

**AITP Mitigation:**

- **Tier 1 quarantine for external data (Section 4.1).** All external data, including data destined for RAG databases, vector stores, and long-term memory systems, enters through Tier 1 agents and is placed in the quarantine buffer. Data is not written to persistent memory until it passes the quarantine scan and Tier 2 review.

- **Cross-architecture review (Section 4.2).** Tier 2 agents reviewing quarantined data operate on different models than Tier 1 agents. A poisoning payload optimized for one model's embedding behavior may be detected by a different model processing the same content.

- **Attestation of memory writes (Section 3.3).** Every write to a persistent memory system (RAG database, vector store, embedding index) produces a signed attestation record. The record includes the input hash, the writing agent's identity, and the timestamp. If poisoned data is detected in a memory system, the attestation chain identifies exactly when it was written, by which agent, from what input source.

- **No shared execution context between tiers (Section 4.4).** Tier 1 agents that ingest external data do not share memory systems with Tier 2 or Tier 3 agents. A poisoned Tier 1 memory cannot directly influence Tier 2 or Tier 3 agent behavior because the tiers operate in isolated execution contexts.

**AITP Trust Risk Parallel:** ATR-07 (Poisonable Context Windows), ATR-08 (Unverified External Data Ingestion).

---

### ASI07: Insecure Inter-Agent Communication

**OWASP Risk Description:**
Multi-agent message exchanges lack proper authentication, encryption, or validation. Agents accept messages from other agents without verifying the sender's identity, the message's integrity, or the sender's authorization to make requests.

**AITP Mitigation:**

- **Cryptographic Agent Identity (Section 3.1).** Every agent holds an Ed25519 key pair. Inter-agent messages can be signed by the sender and verified by the receiver using the sender's registered public key. A message from an unregistered identity is rejected.

- **Attestation for inter-agent communication (Section 3.3).** Every message sent between agents produces a signed attestation record on both ends: the sender attests to sending, and the receiver attests to receiving. The input and output hashes in the attestation records must match, providing cryptographic proof that the message was not modified in transit.

- **Co-signature for consequential inter-agent requests (Section 3.4).** An inter-agent request that triggers a consequential action still requires co-signature. Agent A cannot instruct Agent B to perform a Tier 3 action without Agent B independently verifying the request through the co-signature protocol. Agent B's Signing Authority checks whether Agent A is authorized to request the action and whether the co-signature requirements are met.

- **Scope verification (Section 3.2, Section 3.5).** When Agent A sends a request to Agent B, Agent B's Signing Authority verifies that the requested action falls within Agent B's scope manifest. Even if Agent A is compromised and sends a malicious request, Agent B cannot act on it if the action is outside Agent B's authorized scope.

**AITP Trust Risk Parallel:** ATR-04 (No Cryptographic Identity), ATR-01 (Unsigned Agent Actions).

---

### ASI08: Cascading Failures

**OWASP Risk Description:**
Errors propagate rapidly across interconnected agents. One agent's failure triggers destructive actions across multiple systems. In tightly coupled multi-agent architectures, a single point of failure becomes a system-wide failure.

**AITP Mitigation:**

- **Tier separation as circuit breaker (Section 4.4).** The three operational tiers create architectural boundaries that prevent direct cascade. A failure in Tier 1 (data ingestion) is contained to the quarantine buffer. A failure in Tier 2 (analysis) is contained to the review buffer. Only Tier 3 failures affect external systems, and Tier 3 actions require co-signature.

- **Revocation halts propagation (Section 3.6).** When a failing or compromised agent is detected, its identity is revoked immediately. Revocation freezes all pending actions from that identity. Downstream agents that have not yet consumed the failing agent's output are protected. Downstream agents that have already consumed it are flagged for review through the attestation chain.

- **Co-signature prevents autonomous cascade (Section 5).** A cascading failure in current systems propagates because each agent in the chain acts autonomously on its input. In AITP, consequential actions require co-signature. A failure that causes Agent A to produce anomalous output does not automatically trigger Agent B to execute an anomalous action, because Agent B's action requires co-signature from an independent agent that evaluates the action independently.

- **Anomaly Resolution Agent (Section 6.4).** In the DDA framework, the ARA is specifically designed to handle cascading disagreements. It operates outside the tier pyramid, on a different architecture, and produces one of three defined outcomes per conflict. It fails closed (escalates to human) rather than fail-infinite (looping endlessly). The ARA's maximum iteration cap of 3-5 prevents resolution attempts from themselves becoming a cascading failure.

- **Bounded blast radius through scope and identity (Section 3.1, Section 3.2).** Each agent's failure is bounded by its scope. An agent with "read:database/customers" that fails cannot affect "database/financials". The blast radius is one agent, one key, one scope manifest, not the entire system.

**AITP Trust Risk Parallel:** ATR-09 (No Revocation Mechanism), ATR-05 (Implicit Trust Inheritance).

---

### ASI09: Human-Agent Trust Exploitation

**OWASP Risk Description:**
Users over-trust agent recommendations, allowing attackers to influence human decisions or extract sensitive information through agent-mediated persuasion. The agent becomes a social engineering vector.

**AITP Mitigation:**

- **Attestation provides verification, not trust (Section 3.3).** AITP explicitly separates process integrity from output correctness (Section 8) (OWASP Specification Section 8 / NIST Submission Section 10). A signed attestation proves that a specific agent produced a specific output. It does not certify the output as true. By making the process transparent and verifiable, AITP provides the human with the information needed to calibrate trust: which agent produced this, what was it authorized to do, what model was it running, and what was its input.

- **Co-signature as independent check (Section 5.1).** Before a Tier 3 action based on an agent recommendation reaches the human, it has been co-signed by an independent agent of different architecture. The co-signature is not a correctness guarantee, but it is an independent safety check that reduces the probability of a manipulated recommendation reaching the human unchallenged.

- **Highest-consequence human co-signature (Section 5.2).** For the most consequential actions, the human is not simply trusting the agent's recommendation. The human is cryptographically confirming authorization via an out-of-band channel with a one-time nonce tied to the specific action. This mechanism forces active human engagement rather than passive acceptance.

- **Audit chain enables challenge (Section 3.3).** If a human suspects an agent recommendation was manipulated, the attestation chain provides the evidence needed to investigate: the full input hash, the agent's identity, the scope it operated under, and the co-signer's independent evaluation. The recommendation is challengeable, not authoritative.

**AITP Trust Risk Parallel:** ATR-10 (Human-Out-of-the-Loop), ATR-06 (No Audit Chain).

---

### ASI10: Rogue Agents

**OWASP Risk Description:**
Compromised or misaligned agents persist across sessions while appearing legitimate. Rogue agents silently exfiltrate data, approve harmful actions, or manipulate other agents while maintaining the appearance of normal operation.

**AITP Mitigation:**

- **Cryptographic Agent Identity (Section 3.1).** A rogue agent must hold a valid Ed25519 key pair registered with the Signing Authority. An unregistered agent cannot produce valid attestation records, cannot request co-signatures, and cannot participate in the trust architecture. The Signing Authority rejects all requests from unregistered identities.

- **Attestation as behavioral record (Section 3.3).** Every action the rogue agent takes is recorded in its attestation chain. The chain is append-only and hash-linked. The rogue agent cannot selectively hide actions. If it exfiltrates data, the exfiltration action is attested. If it approves harmful actions, the approval is attested with its identity. The attestation chain is the forensic record that enables detection.

- **Revocation upon detection (Section 3.6).** When rogue behavior is detected (through anomalous attestation patterns, failed cross-tier validation, or human investigation), the agent's identity is revoked immediately. All pending actions are frozen. All downstream agents that consumed the rogue agent's output are flagged through the attestation chain. The compromise window is bounded from detection to revocation.

- **Cross-architecture verification detects misalignment (Section 4.2, Section 5.1).** A rogue agent that passes peer review by agents of the same model may not pass review by agents of a different architecture. The cross-architecture requirement at tier boundaries and in the co-signature protocol increases the probability that subtle misalignment is detected by an agent with different failure modes and biases.

- **Tier reset on recovery (Section 3.6).** A detected rogue agent that is restored to service after investigation re-enters at Tier 1 with a new identity and a new scope manifest. It does not retain any prior trust level. It must re-earn tier promotion through normal operational history.

**AITP Trust Risk Parallel:** ATR-04 (No Cryptographic Identity), ATR-09 (No Revocation Mechanism), ATR-02 (Single-Model Verification).

---

## Coverage Matrix

The following matrix shows which AITP trust primitives and architectural components mitigate each OWASP Agentic risk.

| OWASP Agentic Risk | Agent Identity | Scope Binding | Attestation | Co-signature | Signing Authority | Revocation | Operational Tiers | DDA |
|---|---|---|---|---|---|---|---|---|
| ASI01: Goal Hijack | | | | X | | | X | |
| ASI02: Tool Misuse | | X | | X | X | | X | |
| ASI03: Identity Abuse | X | X | | | | X | | |
| ASI04: Supply Chain | | X | X | X | | X | | |
| ASI05: Code Execution | | X | X | X | X | | X | |
| ASI06: Memory Poisoning | | | X | | | | X | |
| ASI07: Insecure Comms | X | X | X | X | X | | | |
| ASI08: Cascading Failures | X | X | | X | | X | X | X |
| ASI09: Human Trust | | | X | X | | | | |
| ASI10: Rogue Agents | X | | X | | | X | X | |

**Legend:** X = primary mitigation mechanism

---


Note: This matrix shows primary mitigations. Secondary mitigations exist where AITP primitives provide defense-in-depth. For example, Attestation provides secondary mitigation for all ten ASI risks through the tamper-evident audit chain.

## Gap Analysis

AITP provides architectural mitigation for all ten OWASP Agentic Application risks. The following areas represent boundaries of AITP's coverage:

1. **Model-level prompt injection prevention.** AITP does not prevent prompt injection. It contains the blast radius through tier separation, quarantine, and co-signature. Prevention remains an open research problem at the model layer.

2. **Output correctness.** AITP guarantees process integrity, not output quality. A signed, attested, co-verified output can still be wrong (Section 8) (OWASP Specification Section 8 / NIST Submission Section 10). Organizations must combine AITP's trust architecture with domain-specific validation.

3. **Human judgment quality.** AITP can route highest-consequence decisions to a human, but it cannot ensure the human makes a good decision. The human co-signature mechanism ensures engagement, not competence.

4. **Social engineering of human operators.** ASI09 includes the risk of agents manipulating human trust. AITP's attestation chain provides evidence for investigation, but does not prevent a human from trusting a well-crafted but manipulative recommendation in real time.

These gaps are not deficiencies in AITP. They are boundaries between trust infrastructure (what AITP provides) and domain-specific judgment (what organizations must provide). AITP is due process, not a stamp of truth.

---

*AI Trust Protocol (AITP) v0.3, OSInfo Inc., March 2026*
*Licensed under CC BY-SA 4.0*
