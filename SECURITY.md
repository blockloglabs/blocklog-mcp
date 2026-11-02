# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Reporting a Vulnerability

The Blocklog engineering team takes the security of our infrastructure and agent gateways very seriously. If you discover a security vulnerability in the `blocklog-mcp` codebase or associated cryptographic components, please report it privately.

**Do NOT report security vulnerabilities via public GitHub issues.**

### How to Report

Please email your security advisory to:

**founder@blocklogsecurity.com**

If possible, include the following information in your report:
- A description of the vulnerability and its potential impact.
- Detailed reproduction steps, sample payloads, or Proof of Concept (PoC) code.
- MCP transport and mode (`stdio` or `streamable-http`, `enforce` or `audit`).
- Any suggested remediations or mitigations.

### Response Time

- **Acknowledgment**: Within 24-48 business hours.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Disclosure**: Coordinated disclosure with patch release.

---

## Cryptographic Guarantees & Assumptions

- **NFC Canonical Hashing**: All execution payloads and receipts are serialized with sorted JSON keys, compact float representations, and Unicode NFC normalization.
- **Ed25519 Signatures**: Validated with standard 32-byte public keys and 64-byte signatures.
- **RFC 6962 Tree Math**: Merkle audit trees and consistency proofs use RFC 6962 leaf and internal node domain separation prefixes (`0x00` and `0x01`).
- **Single-Use Tokens**: Action execution tokens are authorized once and atomically consumed. Replay attempts must fail closed.
