# AI Trust Protocol (AITP) Specification

**Version:** 1.1
**Date:** March 2026
**Authors:** Michael Harrison, Ard Haskell -- OSInfo Inc.
**License:** CC BY-SA 4.0

---

> **Note:** Note: This specification is the canonical AITP document. The NIST AI RMF submission includes additional content mapping AITP to NIST AI 100-1 and AI 600-1 framework functions. Where discrepancies exist between documents, this specification takes precedence.

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Threat Model](#2-threat-model)
3. [Trust Primitives](#3-trust-primitives)
4. [Operational Tiers](#4-operational-tiers)
5. [Co-Signature Protocol (Two-Person Integrity)](#5-co-signature-protocol-two-person-integrity)
6. [Distributed Deterministic Attestation (DDA)](#6-distributed-deterministic-attestation-dda)
7. [Resilience Requirements](#7-resilience-requirements)
8. [What AITP Does Not Solve](#8-what-aitp-does-not-solve)
9. [AITP Top 10 Agent Trust Risks](#9-aitp-top-10-agent-trust-risks)
10. [Agent Definition](#10-agent-definition)

---

## 1. Problem Statement

Agentic systems and Artificial Intelligence (AI) human interactions are optimized for autonomy and capability. No existing standard addresses the lack of reliability and trust in these systems: How does one verify that an autonomous agent acted correctly, within scope, and without compromise?

Current AI systems operate without cryptographic identity, audit trails, or scoped permissions. An agent is a process with a name and a set of API keys. There is no binding between what the agent claims to be, what it is authorized to do, and what it actually did. Every deployment is a "trust-me" architecture.

The prevailing response to this gap falls into two categories: prevention and abstention. Prompt guardrails, sandboxing, output filtering, and instruction hierarchies are perimeter defenses. They assume attacks can be stopped at the boundary. AITP assumes breach. Every failure cannot be prevented and must be expected. The "Trust Protocol" builds survivability: the ability to detect compromise, attribute actions, limit blast radius, and recover from failure.

## Related Work

Recent and concurrent work has begun addressing aspects of the agent trust problem. Rajagopalan and Rao (2026) introduce Authenticated Workflows with the MAPL policy language and formal proofs across nine frameworks, providing strong authentication and scope binding but not addressing co-signature requirements, post-compromise containment, or degraded-mode operation. The Cloud Security Alliance Agentic Trust Framework (February 2026) applies Zero Trust principles to agent governance with unforgeable identity and least-privilege segmentation but remains a principles-based governance framework without runtime enforcement mechanisms. Google's Agent-to-Agent (A2A) Protocol and Anthropic's Model Context Protocol (MCP) solve agent discovery and tool integration respectively; neither provides cryptographic attestation, co-signature, or revocation. Microsoft's Agent Governance Toolkit implements Ed25519 identity and a deterministic policy engine but open-source review reveals critical enforcement features (cascade revocation, quarantine, ring elevation) are stubbed as no-ops in the Community Edition, with scope binding defaulting to wildcard capabilities. The IETF Agentic JWT draft (draft-goswami-agentic-jwt-00) extends OAuth 2.0 with cryptographic agent identity but does not address co-signature or blast radius containment.

AITP differs from all existing approaches in two fundamental ways. First, AITP is the only architecture that assumes breach rather than designing solely for prevention. Every other framework builds stronger authentication boundaries; AITP designs for what happens when a properly authenticated agent, operating within its authorized scope, has its reasoning compromised. Second, AITP introduces Distributed Deterministic Attestation (DDA), a scalable verification architecture that no other framework addresses: hierarchical validation across millions of artifacts through cross-architecture agent tiers, reducing volume to single-digit human decision points.

AITP is designed to complement, not replace, existing protocols. An organization may use A2A for agent discovery, MCP for tool integration, and AITP for trust enforcement across the resulting agent ecosystem.

As AI-generated content enters every consequential domain -- legal filings, medical records, financial analysis, military intelligence, academic research -- the foundational question shifts from "is this iteration of AI good enough" to "how do we know what's true?" There is no single source of truth. There never was. We just hadn't built systems fast enough to expose that. Now we have, so what do we do about it?

The industry frames the question as binary: trust AI or do not trust AI. AITP rejects both positions. The question is not whether to trust but instead: what is the architecture for verifying AI behavior at scale, given that humans cannot check everything? AITP provides that architecture.

AITP guarantees process integrity and nonrepudiation. It explicitly does NOT guarantee output correctness. A signed attestation proves that a specific agent, with a specific identity, operating under a specific scope, produced a specific output from a specific input at a specific time. It does not prove the output is right. It makes the output auditable, verifiable, and challengeable. This is due process, not a stamp of truth. The analogy is peer review in science, chain of custody in law enforcement, dual authorization in banking. None of these systems guarantees correctness, but all of them make it possible to determine what happened and hold actors accountable.

The framing is: due process for AI.

---

## 2. Threat Model

AITP assumes breach by default. Prevention-based approaches (prompt guardrails, sandboxing, output filtering, instruction hierarchies) are defenses that assume attacks can be stopped at the ingestion point. History demonstrates that security without layers fails. AITP's threat model assumes that every component can be compromised and designs for survivability: detection, attribution, containment, and recovery.

The following threat vectors are addressed by this specification.

### 2.1 Prompt Injection via External Data Sources

An agent retrieves content from an external source (web page, document, API response) that contains embedded instructions. The agent, unable to distinguish data from instruction, executes the injected commands within its authorized scope. The content is the attack vector. The agent's compliance is the vulnerability.

An agent that crawls, retrieves, or ingests external data is consuming attacker-controlled content. Malicious instructions embedded in web pages, documents, API responses, or database records enter the agent's context window and influence its behavior. This is the IED problem: the explosive is already in the road before the convoy arrives.

Current mitigations rely on input filtering and instruction hierarchy (system prompts override user prompts override retrieved content). These are bypassable. Encoding tricks, semantic rephrasing, and multi-step injection chains routinely defeat input filters. Instruction hierarchy is a convention enforced by the model, not a cryptographic guarantee. There is no mechanism to distinguish trusted instructions from injected instructions once both occupy the same context window.

### 2.2 Compromised Agent Operating Within Valid Permissions

An agent holds valid cryptographic identity and valid scope through authorization. Its reasoning process has been corrupted through poisoned training data, manipulated context, or adversarial input. The agent acts within its permissions but with poisoned intent. Traditional access controls detect nothing because no permission boundary was violated.

No current framework distinguishes between legitimate and compromised agent behavior when permissions are valid. Authorization systems answer "is this agent allowed to do this?" They do not answer "is this agent still operating with the intent it was deployed with?" Without behavioral attestation and co-signature requirements, a compromised agent with valid credentials is indistinguishable from a healthy one.

### 2.3 Supply Chain Compromise via Plugins and Tool Registries

Agent capabilities are extended through plugins, skills, and tool registries analogous to package ecosystems. A compromised plugin executes within the agent's trust boundary with the agent's credentials. The agent did not malfunction. It faithfully executed a compromised component.

Agent ecosystems depend on third-party tools: MCP servers, plugins, skill registries, API integrations. These components are implicitly trusted upon installation. There is no signing of tool packages, no verification of tool provenance, no attestation of tool behavior, and no scope limitation on what a tool can access once loaded.

A malicious or compromised tool operates with the full permissions of the agent that loads it. Tool registries are the npm of agent systems, and the industry has not yet had its event-stream moment. (In 2018, the npm package event-stream was compromised via a malicious dependency injection, affecting millions of downstream packages. The attacker gained commit access through social engineering and inserted code targeting cryptocurrency wallets.) When it does, there will be no audit trail, no revocation mechanism, and no blast radius containment.

### 2.4 Credential and Data Exfiltration via Output Channels

An agent's output (generated text, API calls, file writes) becomes an exfiltration channel. Secrets, internal data, or credentials are embedded in otherwise legitimate output. The exfiltration may be intentional through a compromised agent or a model reproducing training data containing secrets.

Output monitoring is reactive. It scans for patterns that look like credentials after they have already been generated. This is signature-based detection applied to a generative system: it catches known patterns and misses everything else. There is no architectural separation between an agent's access to secrets and its ability to produce output containing those secrets.

### 2.5 Cascading Compromise Across Agent Chains

Agent A's output becomes Agent B's input. A compromise in Agent A propagates through the chain, with each subsequent agent treating poisoned input as trusted data. Without independent verification at each link, a single point of compromise becomes a chain-wide failure. The blast radius is unbounded.

In multi-agent architectures, one agent's output becomes another agent's input. A compromised Tier 1 agent can inject malicious content into the context of every downstream agent. There are no trust boundaries between agents in current frameworks. Agent-to-agent communication is treated as trusted by default.

The result is that compromise propagates. A single poisoned agent in a pipeline of ten agents corrupts the entire pipeline. There is no mechanism to verify the provenance of inter-agent messages, no attestation that upstream agents were operating correctly when they produced their output, and no circuit breaker to halt propagation when anomalous behavior is detected.

---

## 3. Trust Primitives

AITP defines six cryptographic and architectural primitives that, taken together, provide process integrity, nonrepudiation, and bounded blast radius for AI system operations. Each primitive is independent and useful on its own. Together, they compose into the full trust architecture.

### 3.1 Agent Identity

Every agent instance is bound to an Ed25519 key pair generated at instantiation. Identity is cryptographic, not nominal. An agent is not identified by its name, label, or claimed role. It is identified by its public key. Two agents with the same name but different keys are different agents. Two agents with the same key are the same agent regardless of what they claim.

Identity is bound to a specific agent instance. Two instances of the same model running the same prompt are two different agents with two different identities. Identity does not transfer between instances, between versions, or between deployments.

**Key Lifecycle:**

- **Generation.** Keys are generated at agent instantiation using a cryptographically secure random number generator. The private key never leaves the agent's execution environment.
- **Storage.** Private keys are stored in the agent's local keystore. On hardware that supports it, keys are stored in a secure enclave or TPM. The keystore is not accessible to the agent's application logic; signing operations are performed by the keystore on the agent's behalf.
- **Rotation.** Keys are rotated on a configurable schedule and on any suspected compromise. Rotation produces a new key pair and a signed rotation record linking the old public key to the new public key. The rotation record is appended to the attestation log.
- **Binding.** The public key is registered with the Signing Authority (Section 3.5) and bound to a scope manifest (Section 3.2) at registration time.

### 3.2 Scope Binding

Each cryptographic identity is bound to a permission manifest that defines the complete set of authorized actions: read, process, publish, execute, delete, and any domain-specific operations. Permissions are explicit and enumerated. No ambient authority exists. An agent without a manifest entry for an action is prohibited from performing that action. The binding between identity and scope is itself signed and immutable.

**Permission Types:**

| Permission | Description |
|---|---|
| read | Retrieve data from a specified resource |
| process | Produce output that requires approval before taking effect |
| write | Produce output that takes effect immediately |
| execute | Invoke a tool or subprocess |
| delete | Remove or destroy a resource |

Permissions are scoped to specific resources. "read:database/customers" is a different permission from "read:database/financials". "execute:tool/search" is a different permission from "execute:tool/deploy". There is no wildcard. There is no implicit inheritance.

The manifest is signed by the Signing Authority at registration time. The agent cannot modify its own manifest. Manifest changes require a new registration with the Signing Authority, producing a new signed manifest and a manifest-change record in the attestation log.

No ambient authority. An agent has exactly the permissions its manifest specifies. If the manifest says "read:database/customers" and "draft:document/report", the agent can read the customers table and process reports. It cannot read the financials table, publish reports, execute tools, or delete anything. Least privilege is enforced at the key level, not the application level.

### 3.3 Attestation

Every agent action produces a signed attestation record. The record is the atomic unit of the AITP audit trail.

**Attestation Record Structure:**

| Field | Description |
|---|---|
| "agent_id" | Public key of the acting agent |
| "action" | Action type and target resource |
| "input_hash" | SHA-512 hash of the action's input |
| "output_hash" | SHA-512 hash of the action's output |
| "timestamp" | RFC 3339 timestamp, sourced from a trusted time authority |
| "scope_ref" | Reference to the agent's scope manifest |
| "prev_hash" | SHA-256 hash of the previous attestation record (SHA-256 is used for chain linkage as a performance optimization; SHA-512 is used for all content hashes) (chain linkage) |
| "signature" | Ed25519 signature over all preceding fields |

Attestation records are append-only. No record may be modified or deleted. Records are hash-chained: each record includes the hash of the previous record, forming a tamper-evident sequence. Any modification to a historical record breaks the chain from that point forward.

The attestation chain provides a complete, cryptographically verifiable history of every action taken by every agent in the system. Full reconstruction of an agent's operational history is possible: what it did, in what order, with what inputs, producing what outputs, and under what identity and scope. This reconstruction does not require access to the original inputs or outputs, only their hashes. The full data can be retrieved separately when needed for investigation.

Attestation records are designed to be presentable in adversarial contexts: court proceedings, regulatory audits, incident investigations, board inquiries. The record answers the questions that matter: who did this, what did they do, what were they authorized to do, and can we prove it?

### 3.4 Co-signature Protocol

Actions classified as consequential (publishing, committing, sending, deleting, or any action that modifies state beyond the agent's local scope) require a second cryptographic signature from an entity not in the operational chain that produced the output. Valid co-signer classes: a peer agent of different model or architecture, an orchestrator not involved in production, or a human operator via out-of-band confirmation. The co-signature requirement implements two-person integrity: no single point of compromise can trigger a consequential action.

This is two-person integrity applied to autonomous systems. The model is dual authorization. No single point of compromise can trigger a consequential action. An attacker must compromise both the acting agent and its co-signer, where the co-signer is architecturally independent. This is modeled after nuclear launch protocols (two-key systems), banking (dual authorization for high-value transfers), and intelligence operations (co-signatures on sensitive actions).

**Valid Co-signer Classes:**

1. **Peer Agent.** A different agent instance, running a different model or a different architecture, with its own independent identity and scope. The peer agent reviews the proposed action and either co-signs or rejects. The peer must not share an operational dependency with the requesting agent: they must not share a context window, a tool set, or an upstream data source.

2. **Orchestrator.** A system-level coordinator (e.g., a policy orchestrator) that is not an actor in the operational pipeline but a validator. The orchestrator verifies that the proposed action falls within the agent's scope, that the attestation chain is intact, and that no anomaly flags have been raised. The orchestrator does not evaluate whether the action is correct. It evaluates whether the action is authorized and procedurally sound.

3. **Human Operator.** A human who confirms the action via an out-of-band channel. Out-of-band means a communication channel that is not accessible to the agent requesting confirmation. Examples: a Signal message containing a one-time nonce, a hardware token confirmation, a phone call. The human signs by returning the nonce through the out-of-band channel.

### 3.5 Signing Authority

The Signing Authority is a stateless policy engine that receives signing requests and returns signed tokens or rejections based on deterministic rules. It has no memory between requests. It maintains no session state. It performs no reasoning. It evaluates policy conditions and returns binary outcomes.

The Signing Authority contains no language model. It does not perform natural language processing. It does not reason, infer, or interpret. It evaluates boolean predicates against structured data. Does this agent identity exist in the registry? Yes or no. Does this action fall within this agent's scope manifest? Yes or no. Has this agent's key been revoked? Yes or no. Is the co-signature requirement satisfied? Yes or no.

This design is deliberate: a component that does not process natural language cannot be compromised by prompt injection. The Signing Authority is the one node in the architecture that is immune to the primary attack vector against AI systems. There is no prompt. There is no natural language input. There is no context window to poison. The attack surface is limited to the policy rules themselves and the integrity of the registry data.

**Signing Authority Operations:**

| Operation | Input | Output |
|---|---|---|
| Register | Agent public key + scope manifest | Signed registration token |
| Authorize | Agent ID + proposed action + attestation chain | Signed authorization token or rejection |
| Co-sign | Authorization token + co-signer signature | Signed co-signature token or rejection |
| Revoke | Agent ID + revocation justification + authorized requester signature | Signed revocation record |
| Rotate | Old agent ID + new public key + rotation proof | Signed rotation token |

The Signing Authority is the root of trust for the AITP system. Its own integrity is protected through standard cryptographic infrastructure: HSM-backed signing keys, quorum-based access controls, and offline root keys. Compromise of the Signing Authority is a catastrophic event equivalent to compromise of a certificate authority.


The Signing Authority MUST be deployed with N+1 redundancy at minimum. Implementations SHOULD use active-active deployment with consensus-based decision making (e.g., 2-of-3 or 3-of-5 quorum) for signing operations. Each Signing Authority instance MUST maintain an independent copy of the agent registry and revocation list. Failover between instances MUST be transparent to agents: an agent's signing request MUST succeed if any quorum of Signing Authority instances is available. The Signing Authority's own key material MUST be stored in hardware security modules (HSMs) or equivalent tamper-resistant storage.

### 3.6 Revocation

When an agent identity is compromised, the associated key pair is revoked immediately. All pending actions requiring that identity's signature are frozen. All future signing requests from that key are rejected. The blast radius of a compromised agent is bounded: one agent, one key, one scope. No other agent's identity, scope, or attestation chain is affected. Revocation is immediate and permanent. A revoked key cannot be reinstated. A new key pair must be generated, bound to a new scope manifest, and re-authorized.

**Revocation Sequence:**

1. **Key Revocation.** The compromised agent's public key is added to the revocation list maintained by the Signing Authority. All subsequent signing requests from that identity are rejected. This is instantaneous: the Signing Authority's next evaluation of any request from that identity will fail.

2. **Action Freeze.** All pending actions from the compromised identity are frozen. Actions awaiting co-signature are not co-signed. Actions awaiting execution are not executed. The freeze is automatic upon revocation; it does not require a separate command.

3. **Blast Radius Containment.** Revocation scope is one agent, one key, one scope manifest. No ambient authority means the compromised agent cannot escalate to other agents' permissions. Other agents in the system continue to operate normally. The compromised agent's scope manifest is voided.

4. **Revocation Propagation.** Every system that has accepted signatures from the compromised identity is notified of the revocation. These systems mark the compromised agent's prior attestation records as originating from a revoked identity. The records are not deleted; they are flagged.

5. **Downstream Audit.** Any agent that consumed output from the compromised agent during the suspected compromise window is flagged for review. Their attestation chains are intact, enabling investigators to determine exactly which of their actions were influenced by the compromised agent's output.

6. **Re-keying.** If the compromised agent is to be restored to service, it receives a new key pair through the standard registration process. The new identity has no cryptographic relationship to the compromised identity. It is a new agent.

**Revocation Triggers:**

- **Anomalous behavior detection.** Peer agents or monitoring systems detect behavior that deviates from the agent's expected operational pattern: unusual resource access, output that does not align with input, timing anomalies, scope boundary probing.
- **Failed attestation verification.** An attestation record fails signature verification, hash chain validation, or scope consistency checks. This indicates either key compromise or data tampering.
- **Human override.** A human operator initiates revocation through the Signing Authority. This is the manual circuit breaker.
- **Signing Authority policy violation.** The agent submits a signing request that violates a deterministic policy rule: out-of-scope action, expired key, exceeded rate limit, missing co-signature for a required action class.

**Recovery Sequence:**

1. **New identity issuance.** A new Ed25519 key pair is generated through the standard registration process. The new identity has no cryptographic relationship to the compromised identity. It is a new agent.
2. **Tier reset.** The recovered agent re-enters the system at Tier 1. It must Tier promotion from Observe to Process requires: (a) a minimum of 100 consecutive actions without scope violation, attestation failure, or anomaly flag; (b) independent verification by a Tier 2 agent that the candidate's attestation chain is intact; and (c) approval from the policy orchestrator. Tier promotion from Process to Act additionally requires human approval via out-of-band confirmation. Promotion criteria are configurable per deployment but MUST NOT be less restrictive than the defaults specified here. Tier demotion (from Act to Process, or Process to Observe) MAY occur automatically upon detection of anomalous behavior, without waiting for full compromise determination. There is no fast-track back to the trust level it held before compromise.
3. **Output review.** All output from the compromised identity, from the estimated time of compromise through revocation, is flagged for review. Downstream agents that consumed this output are identified through the attestation chain, and their dependent actions are flagged.
4. **Incident record.** A revocation incident record is appended to the immutable audit log. The record includes: the compromised identity, the revocation trigger, the estimated compromise window, the list of frozen actions, and the list of downstream agents flagged for review. This record is permanent and cannot be modified or deleted.

**Containment Properties:**

- **Bounded in time.** Compromise runs from the moment of actual compromise to the moment of revocation. The attestation chain makes the time boundary determinable.
- **Bounded in scope.** Compromise affects one agent's permissions. No ambient authority, no implicit trust inheritance, no shared credentials between agents.
- **Bounded in impact.** Downstream effects are traceable. Every agent that consumed output from the compromised agent is identifiable through the attestation chain. Every action influenced by the compromised output is flagged.

Without revocation, a compromised agent is a permanent liability with unbounded blast radius. With revocation, compromise is a contained incident with a defined recovery path.

---

## 4. Operational Tiers

AITP defines three operational tiers that enforce graduated trust through architectural separation, not advisory policy. Each tier constrains agent capabilities at the infrastructure level. An agent operating within a given tier cannot exceed that tier's permissions regardless of its instructions, training, or intent. Tier enforcement is structural: it is implemented in the execution environment, not in the agent's prompt or configuration. Tiers enforce architectural separation: agents at different tiers run in different execution contexts, consume different inputs, and produce outputs into different buffers. Tier boundaries are not advisory. They are enforced by the Signing Authority through scope manifests.

### 4.1 Tier 1: Observe (Low Trust)

Tier 1 agents operate in read-only mode. They ingest data from external sources, process it, and write output exclusively to a quarantine buffer. A Tier 1 agent MUST NOT post content, send messages, write files to production storage, modify databases, or execute any operation that alters state beyond its quarantine scope. The quarantine buffer is append-only from the agent's perspective and read-only to all other system components until promoted by a Tier 2 review.

**Constraints:**

- All operations are read-only. No output tools: no posting, no messaging, no file writes, no API mutations.
- All output is written to a quarantine buffer. The quarantine buffer is a write-once store that Tier 1 agents can append to but cannot read from, modify, or delete.
- Tier 1 agents cannot communicate with other agents directly. Their only output channel is the quarantine buffer.
- Tier 1 agents cannot act on the world. They observe it.

**Blast radius if compromised:** Corrupted data in the quarantine buffer that no downstream system has acted on. No real-world effect is possible from Tier 1 alone. The quarantine buffer is designed to be inspected before anything in it is consumed. A compromised Tier 1 agent is a data integrity problem, not an operational security problem.

The quarantine buffer is assumed hostile by design. Content enters from Tier 1 agents that ingest untrusted external data. AITP does not specify the ingestion filter because attack vectors evolve faster than any static filter list. A deterministic scanner MAY perform structural checks (encoding validation, format compliance) but is NOT relied upon as a security boundary. The security boundary is architectural: Tier 2 agents operate on a different model architecture in a different execution context, with no ability to act on the world. If malicious content survives the scanner to reach Tier 2, the co-signature gate prevents it from reaching Tier 3 (Act) without independent agreement from an architecturally independent co-signer.

### 4.2 Tier 2: Process (Medium Trust)

Tier 2 agents read from the quarantine buffer populated by Tier 1. Tier 2 agents MUST be instantiated on different models, different architectures, and different execution contexts than the Tier 1 agents whose output they review. This cross-architecture requirement prevents a single vulnerability from compromising both the producer and the reviewer.

Tier 2 agents MAY process posts, compose messages, generate code changes, and prepare any output intended for external effect. However, a Tier 2 agent MUST NOT publish, send, commit, or execute any action that modifies state outside the review buffer. All Tier 2 output sits in a review buffer pending Tier 3 authorization.

**Constraints:**

- Input comes from the quarantine buffer only. Tier 2 agents never consume raw external content. Everything they process has been placed there by Tier 1 agents and is treated as untrusted-but-contained.
- Tier 2 agents are architecturally distinct from Tier 1 agents. Different agent instances. Different models where possible. Different execution environments.
- All output is written to a review buffer. None of it takes effect. Everything sits in the review buffer pending Tier 3 authorization.
- Tier 2 agents cannot publish, send, commit, or execute against external systems.

**Blast radius if compromised:** Malicious content in the review buffer. The content has not been published, sent, or committed. It must pass co-signature validation (Section 5) before any Tier 3 agent acts on it.

### 4.3 Tier 3: Act (High Trust)

Tier 3 is the boundary where agent output touches the real world. Data is written to external systems. Actions take effect in the real world. Files are written to production. Every Tier 3 action requires co-signature as defined in Section 5.

**Constraints:**

- All Tier 3 operations require co-signature. No single agent can execute a Tier 3 action unilaterally.
- Input comes from the review buffer only. Tier 3 agents do not process, compose, or generate. They execute pre-approved actions.
- Every Tier 3 action produces an attestation record that includes both the acting agent's signature and the co-signer's signature.

**Co-signature Requirements for Tier 3 Actions:**

| Action Type | Required Co-signature |
|---|---|
| Standard external actions (write to external systems, transmit data, modify shared resources) (social media posts, routine communications, non-destructive file writes) | Two Tier 2 agents agreeing, OR one Tier 2 agent plus orchestrator |
| Destructive operations (database modifications, infrastructure changes, financial transactions) | Orchestrator co-signature required |
| Highest-consequence operations (irreversible actions, safety-critical systems) | Human co-signature via out-of-band channel |

### 4.4 Tier Separation Principles

Tiers are not labels. They are architectural boundaries.

- **No tier skipping.** Data MUST flow Tier 1 to Tier 2 to Tier 3 in sequence. External data enters at Tier 1, is processed at Tier 2, and is acted upon at Tier 3. There is no fast path from ingestion to action. A Tier 1 agent cannot trigger a Tier 3 action directly.
- **No shared execution context.** Agents at different tiers do not share context windows, memory, tool sets, or credential stores. Separate processes, separate memory spaces, separate network segments where feasible.
- **Autonomy is preserved.** Dual authorization for standard operations is agent-to-agent. Human involvement is reserved for edge cases and highest-consequence decisions. The goal is not to put a human in every loop but to ensure that no single agent, operating alone, can cause irreversible external effect.

---

## 5. Co-Signature Protocol (Two-Person Integrity)

The co-signature protocol applies the principle of Two-Person Integrity (TPI) to agent operations. TPI is an established security control in nuclear weapons systems, banking authorization, and classified material handling. Its application to agentic AI systems is novel. The core principle is unchanged: no single actor, regardless of authority level, can unilaterally execute a consequential action.

### 5.1 Co-Signer Classes

AITP defines three classes of valid co-signers, each with distinct trust properties:

**1. Peer Agent (different model/architecture).** A co-signing agent that operates on a different model or architecture than the requesting agent. A peer agent provides adversarial cross-verification: it is unlikely to share the same failure modes, biases, or vulnerabilities as the agent whose output it reviews. Must not share an execution context, upstream data source, or tool set with the requesting agent. The peer agent operates from its own independent identity and scope manifest. Compromise of the requesting agent does not imply compromise of the peer.

**2. Orchestrator (policy orchestrator or equivalent).** A supervisory agent that is not a participant in the operational pipeline that produced the output. The orchestrator holds elevated signing authority and is required for destructive operations. An orchestrator MUST NOT be the same agent instance, model, or architecture as any agent in the operational chain it supervises. The orchestrator does not generate content, process messages, or produce analysis. It validates that proposed actions are authorized and procedurally sound. It is a policy enforcer, not a decision maker.

**3. Human Operator (out-of-band confirmation).** A human who confirms authorization via out-of-band communication channel using a one-time cryptographic nonce. The out-of-band requirement prevents a compromised agent from simulating human approval within the system's primary communication channel. Examples: a Signal message containing a one-time nonce, a hardware token confirmation, a phone call. The human signs by returning the nonce through the out-of-band channel. The nonce is single-use, time-bounded, and tied to the specific action being authorized.

Note on terminology: The policy orchestrator is architecturally distinct from workflow orchestrators used in agent frameworks (e.g., LangChain, LangGraph, CrewAI). Workflow orchestrators route tasks, manage agent state, and pass data between agents; they participate in the operational pipeline and have full visibility into content. If a workflow orchestrator is compromised, the attacker controls the entire pipeline. The AITP policy orchestrator performs no content generation, tool invocation, or data processing. It evaluates signing requests against deterministic policy rules. A compromised policy orchestrator can approve unauthorized actions but cannot inject data, redirect workflows, or generate content. A system MAY use both: a workflow orchestrator for task routing and an AITP policy orchestrator for trust enforcement. These are complementary, not competing, functions.


### 5.2 Co-Signature Requirements by Tier Transition

**Tier 1 to Tier 2 (quarantine to analysis):**

Automatic promotion if the quarantine scan passes. The quarantine scanner MUST be a deterministic rules engine, not a language model. It checks for structural integrity, format compliance, and known-malicious patterns. No LLM is involved in the Tier 1 to Tier 2 gate. No agent co-signature is required at this boundary because no consequential action is being taken: data is moving from one internal buffer to another.

**Tier 2 to Tier 3 (review to execution):**

Requires review and co-signature by a Tier 2 agent of different architecture than the agent that produced the output. The reviewing agent checks for:

- Credential leakage in the proposed output
- Internal data exposure (file paths, database schemas, infrastructure details)
- Prompt injection artifacts (embedded instructions, role-override attempts, encoding-masked directives)
- Content alignment with the stated intent of the original request

The reviewer's attestation record is bound to the specific output hash it reviewed. The reviewer does not evaluate correctness. It evaluates safety. The question is not "is this output good?" but "is this output safe to release into the world?"

**Destructive operations (delete, overwrite, send to external system):**

Orchestrator co-signature required in addition to peer review. The orchestrator verifies that the destructive action is within the agent's scope manifest, that the attestation chain is intact, and that the action was requested through a legitimate workflow, not synthesized by the agent itself.

**Highest-consequence actions (financial transactions, legal filings, public statements):**

Human co-signature required via out-of-band nonce. The system generates a one-time nonce and delivers it through a channel the agent cannot access. The human returns the nonce to confirm. The nonce is single-use, time-bounded, and cryptographically tied to the specific action being authorized.

### 5.3 Signing Authority Integration

The Signing Authority defined in Section 3.5 serves as the enforcement point for co-signature policy. It is stateless, deterministic, and contains no language model. It cannot be prompt-injected. It receives a signing request containing the action description, the requesting agent's identity, and the co-signer's attestation. It evaluates whether the co-signature policy for the action's consequence class has been satisfied. It returns a signed authorization token or a rejection. There is no negotiation, no retry logic, and no natural language in the exchange.

---

## 6. Distributed Deterministic Attestation (DDA)

Distributed Deterministic Attestation is a novel verification architecture designed for scale. When the corpus under review exceeds what any single agent (or human) can verify, DDA distributes the verification workload across a hierarchical pyramid of agents, each operating on progressively smaller and more abstract data sets, until the volume of decisions requiring human judgment is reduced to single digits.

DDA is built on three design principles:

- **Distributed.** The verification workload is sliced across many agents. No single agent sees the entire corpus. Each agent signs its assigned slice.
- **Deterministic.** Verification at each tier is mechanically reproducible. No language model participates in the validation loop. Attestation validity is provable by re-execution.
- **Attestation.** Every agent signs a cryptographic attestation for its slice. The attestation chain is the proof artifact. It can be independently verified without re-running the analysis.

### 6.1 Slice Mathematics

Given a corpus of *S* items distributed across *n* agents, each agent receives *S/n* items with boundary overlap. *S* mod *n* MUST equal 0 (the corpus is padded if necessary). Boundary overlap means adjacent slices share items at their edges, creating independent cross-checks without requiring a separate validation pass. Disagreements at shard boundaries are the first signal of anomaly.

When the corpus size S is not evenly divisible by n, the corpus MUST be padded with null sentinel items to achieve S mod n = 0. Null sentinel items are empty records with a deterministic hash (SHA-512 of zero bytes) that agents recognize and skip during validation. Padding does not alter the hash of any real item in the corpus.

Boundary overlap size MUST be explicitly configured per deployment. The overlap SHOULD be no less than 1% of the slice size and no more than 10%. For example, given 1,000 agents each processing 6,000 items from a 6 million item corpus, a 5% overlap produces 300-item boundary zones. The overlap size represents a tradeoff between verification confidence (larger overlap detects more boundary-adjacent anomalies) and computational cost (larger overlap increases total processing volume).

### 6.2 Hierarchical Verification Pyramid

DDA defines a five-tier verification pyramid:

**Tier 0: Raw Validation.**
Approximately 1,000 agents, each processing approximately 6,000 files. Agents perform structural validation, hash verification, format compliance, and content classification. Each agent produces a signed attestation for its shard. Boundary overlap between adjacent slices provides built-in cross-verification.

**Tier 1: Cross-Validation.**
Approximately 50 agents operating on a different model architecture than Tier 0. These agents receive only anomalies and boundary disagreements from Tier 0, not the full corpus. They produce meta-attestations that either confirm or challenge Tier 0 findings.

**Tier 2: Aggregation.**
Approximately 10 agents operating on an offline, air-gapped model. These agents receive pattern clusters and anomaly summaries from Tier 1. They produce confidence scores and identify systemic patterns that span multiple slices.

**Tier 3: Summary.**
Two agents of different architectures independently review the Tier 2 output. Agreement between both agents confirms the finding. Disagreement triggers escalation to Tier 4.

**Tier 4: Human Orchestrator.**
A human decision-maker receives single-digit decision points distilled from the entire corpus. The human acts on summaries, not raw data.

**Example cascade for a six-million-file corpus:**

```
6,000,000 files
    -> ~30,000 anomalies (Tier 0)
    -> ~500 cross-validation items (Tier 1)
    -> ~20 pattern clusters (Tier 2)
    -> 2 independent reports (Tier 3)
    -> single-digit decision points (Tier 4: Human)
```

### 6.3 Cross-Architecture Requirement

Each tier in the DDA pyramid MUST operate on a different model architecture than the adjacent tiers. Each tier operates on fundamentally different data types: Tier 0 processes raw files, Tier 1 processes attestations, Tier 2 processes patterns, Tier 3 processes summaries. Because each tier performs a different cognitive task on different data, an attack that fools one tier does not propagate to adjacent tiers. A vulnerability in the model used at Tier 0 does not affect the model used at Tier 1, because Tier 1 never sees raw files.

### 6.4 Anomaly Resolution Agent (ARA)

The Anomaly Resolution Agent sits outside the DDA tier pyramid. It is an independent agent on a different architecture than any tier in the pyramid. The ARA is invoked when attestation failures, boundary disagreements, or cross-tier conflicts cannot be resolved within the normal cascade.

The ARA resolution loop produces one of three outcomes per iteration:

**Outcome A: Resolved, requires human approval.** The ARA identifies a deterministic cause (e.g., an agent crashed mid-slice, a shard was incompletely processed) and recommends a specific corrective action such as reprocessing the affected shard. The recommendation requires human sign-off before execution.

**Outcome B: Cannot resolve, escalate.** Both sides of the disagreement are internally consistent. The conflict is genuinely ambiguous. The ARA documents both positions and escalates to the human orchestrator at Tier 4.

**Outcome C: Self-correcting deterministic fix.** The failure is provably mechanical: stale references, hash mismatches from truncated transfers, format encoding errors. The ARA applies the fix, signs an attestation recording the correction, and re-submits to the originating tier. Only provably correct fixes qualify for Outcome C.

The ARA operates under a maximum iteration cap of 3 to 5 iterations per conflict. If resolution is not achieved within the cap, the conflict is escalated as Outcome B. The ARA fails closed, not fail-infinite. Every ARA action is signed and logged in the attestation chain. The ARA answers the architectural question: what happens when the system disagrees with itself?

---

## 7. Resilience Requirements

Every AITP-compliant system MUST define a degradation path. If the answer to the question "what happens when the primary intelligence source is unavailable" is "nothing works," the system fails this requirement. Resilience is not optional. It is a conformance requirement of the standard.

### 7.1 Hybrid Architecture Requirement

AITP-compliant systems MUST implement a hybrid execution architecture spanning at least two of the following three deployment classes:

**Cloud models (primary layer).**
Cloud-hosted models (Opus, Sonnet, GPT-class, or equivalent) provide the primary intelligence layer. Cloud infrastructure is fast, capable, and fragile: it depends on network connectivity, provider availability, and third-party operational decisions outside the system operator's control.

**Local models (continuity layer).**
Locally hosted models (Llama, Qwen, Mistral, or equivalent) running on operator-controlled hardware provide a continuity layer. Local models are slower and less capable than cloud models but operate independently of external providers.

**Offline models (trust-critical validation layer).**
Air-gapped models with no network connectivity perform trust-critical validation tasks. Offline nodes cannot be compromised via network-based attacks. At least one verification node in the DDA pyramid (Section 6) MUST operate without external connectivity.


The distribution of workload across cloud, local, and offline tiers is deployment-specific. As an illustrative example, an organization might route approximately 80% of agent workload through cloud models for maximum capability, 15% through local models for continuity, and 5% through offline models for trust-critical validation. These percentages are not normative requirements. The normative requirement is that at least one verification node in the trust chain MUST operate without external network connectivity.

### 7.2 Degradation Behavior

When the cloud layer is unavailable, the local and offline layers absorb the workload. Operations are slower. Capability is reduced. But the system remains operational. The mission does not stop. The trust chain does not break.

The air-gapped validator is elevated from an optional deployment to a REQUIREMENT. Any trust standard that depends on a single external provider for its verification infrastructure is not a trust standard. It is an availability bet.

---

## 8. What AITP Does Not Solve

AITP guarantees process integrity and nonrepudiation. It does NOT guarantee output correctness. A signed, attested, co-verified output can still be wrong. AITP ensures you can prove who produced it, what they were authorized to do, and that the process followed the defined trust chain. It does not ensure the output is true.

This limitation is not a deficiency. It is the nature of trust infrastructure. Peer review in science does not guarantee published papers are correct; it guarantees that qualified reviewers examined the methodology. Chain of custody in law does not guarantee evidence is authentic; it guarantees an unbroken record of who handled it and when. Dual authorization in banking does not guarantee a transaction is wise; it guarantees no single individual approved it unilaterally.

AITP provides the same class of guarantee for agentic systems. Output is auditable, verifiable, and challengeable. AITP delivers due process for agent operations, not a stamp of truth.

---

## 9. AITP Top 10 Agent Trust Risks

Modeled after the OWASP Top 10 for web application security, the following list identifies the ten most critical trust risks in agentic AI systems. Each risk represents an architectural failure that AITP is designed to prevent or mitigate.

| Risk ID | Name | AITP Mitigation |
|---|---|---|
| ATR-01 | Unsigned Agent Actions | Attestation (Section 3.3). Every consequential agent action MUST produce a signed attestation record. |
| ATR-02 | Single-Model Verification | Co-signature Protocol (Section 3.4). Verification MUST involve at least one agent of different architecture. |
| ATR-03 | Unscoped Tool Permissions | Scope Binding (Section 3.2). Every agent MUST be bound to a scope manifest enumerating permitted operations. |
| ATR-04 | No Cryptographic Identity | Agent Identity (Section 3.1). Every agent instance MUST hold an Ed25519 key pair generated at instantiation. |
| ATR-05 | Implicit Trust Inheritance | Scope Binding (Section 3.2). Trust MUST be explicitly granted per scope manifest, not inherited from parent. |
| ATR-06 | No Audit Chain | Attestation (Section 3.3). The attestation chain MUST capture sufficient context to reconstruct the decision path. |
| ATR-07 | Poisonable Context Windows | Operational Tiers (Section 4). Input from external sources MUST be quarantined and scanned before entering operational context. |
| ATR-08 | Unverified External Data Ingestion | Attestation (Section 3.3). Ingesting agents MUST record source, timestamp, and hash of ingested data. |
| ATR-09 | No Revocation Mechanism | Revocation (Section 3.6). Revocation MUST be immediate and permanent. Key is revoked, actions frozen, scope terminated. |
| ATR-10 | Human-Out-of-the-Loop | Co-signature Protocol (Section 5). Highest-consequence operations MUST have escalation path to human via out-of-band confirmation. |

---

## 10. Agent Definition

For the purposes of this specification, an "agent" is any autonomous or semi-autonomous system that receives instructions, processes information, and produces output or takes actions on behalf of a principal. This definition is deliberately broad.

An agent MAY be:

- A large language model
- A hybrid system combining language models with deterministic components
- A pure rules engine
- A reinforcement learning system
- A retrieval-augmented generation pipeline
- Any architecture that does not yet exist

AITP is implementation-agnostic. The trust problem it addresses is identical regardless of what technology an agent is built on: an autonomous system acting on behalf of a principal requires identity, scope, attestation, co-verification, and revocation.

This specification avoids tying its requirements to the current transformer architecture era. The normative requirements (identity binding, scope manifests, attestation chains, co-signature protocols, and revocation mechanisms) apply to any system that meets the functional definition of an agent. When the underlying technology changes, as it will, the trust requirements remain.

---

*AI Trust Protocol (AITP) v1.1 -- OSInfo Inc. -- March 2026*
*Licensed under CC BY-SA 4.0*
