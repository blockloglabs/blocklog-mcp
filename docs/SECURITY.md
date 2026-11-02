# Blocklog MCP Security & Cryptographic Model

This document outlines the security architecture, threat model, cryptographic primitives, and verification algorithms implemented in the **Blocklog Model Context Protocol (MCP) Server**.

---

## 1. Threat Model & Trust Boundaries

The Blocklog MCP Server acts as an authoritative security boundary between non-deterministic AI agent reasoning loops and consequential execution environments.

```
+─────────────────────────+
|   AI Agent (Untrusted)  |
|  - Prompt Injection     |
|  - Hallucination        |
|  - Parameter Tampering  |
+────────────┬────────────+
             │ MCP Calls
             ▼
+─────────────────────────+
|   Blocklog MCP Server   | <── Enforcement & Verification Boundary
+────────────┬────────────+
             │ Authenticated HTTPS / HMAC
             ▼
+─────────────────────────+
| Blocklog Control Plane  |
|  - Policy Engine        |
|  - Single-Use Tokens    |
|  - Merkle Audit Ledger  |
+─────────────────────────+
```

### Potential Threats & Mitigations

1. **Parameter Alteration / Argument Tampering**:
   - *Threat*: Agent alters parameters between permission evaluation and execution.
   - *Mitigation*: The prepare phase hashes canonical NFC arguments into an `expected_args_hash`. The execution phase verifies that the incoming execution arguments match this hash exactly before consuming the token.

2. **Replay Attacks**:
   - *Threat*: Malicious agent or intercepted payload attempts to repeat a financial or data-altering action.
   - *Mitigation*: Single-use execution tokens are atomically consumed on the authoritative backend. Replayed tokens immediately fail closed.

3. **LLM Self-Approval Exploitation**:
   - *Threat*: Agent attempts to approve its own flagged action via tool calls.
   - *Mitigation*: The MCP server strictly exposes review requests (`blocklog_request_approval`) and read-only status checks. Decisions can only be executed by human reviewers through authenticated external channels.

4. **DNS Rebinding & Host Header Injection**:
   - *Threat*: Malicious browser scripts accessing the local MCP HTTP daemon.
   - *Mitigation*: Host header validation (`BLOCKLOG_HTTP_ALLOWED_HOSTS`) rejects any request with an unrecognized `Host` header.

---

## 2. Cryptographic Specifications

### 2.1 Canonical JSON Encoding (RFC 8785) & NFC Normalization
To ensure consistent hashing across diverse programming environments (Rust, Python, Go, TypeScript), payloads are normalized before hashing:
1. **Unicode NFC**: All string fields are normalized into Unicode Canonical Composition (NFC).
2. **Lexicographical Key Sorting**: Object keys are sorted strictly by UTF-8 byte order.
3. **Number Formatting**: Floats and integers follow strict decimal serialization without unnecessary exponents or trailing zeros.
4. **Whitespace Elimination**: All structural whitespace between separators (`:`, `,`) is stripped.

### 2.2 RFC 6962 Merkle Audit Trees
The ledger uses Certificate Transparency (RFC 6962) hashing:
- **Leaf Hash**:
  $$\text{LeafHash}(M) = \text{SHA-256}(0x00 \mathbin{\Vert} M)$$
- **Internal Node Hash**:
  $$\text{NodeHash}(L, R) = \text{SHA-256}(0x01 \mathbin{\Vert} L \mathbin{\Vert} R)$$
- **Domain Separation**: The single prefix byte prevents second preimage attacks.
- **Inclusion Proofs**: The server verifies Merkle audit paths up to the published tree root size and root hash.

### 2.3 Ed25519 Digital Signatures
- Authoritative execution receipts are signed with Ed25519 private keys stored on hardware security modules (HSM) or secure key vaults.
- Receipts carry standard 32-byte public keys and 64-byte detached signatures.
- Local verification uses the pure-Rust `ed25519-dalek` crate with zero network dependencies.
- Multi-anchor trust roots allow separate validation of primary tenant signers, third-party witness notaries, and external counterparties.
