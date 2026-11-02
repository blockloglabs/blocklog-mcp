# Contributing to Blocklog MCP Server

Thank you for your interest in contributing to the **Blocklog Model Context Protocol (MCP) Server** (`blocklog-mcp`)! This document provides guidelines for setting up your environment, writing code, running tests, and submitting contributions.

---

## Development Setup

### Prerequisites

- **Rust**: Version 1.88 or later (stable toolchain recommended)
  ```bash
  rustup update stable
  rustup component add rustfmt clippy
  ```
- **Git**: 2.30+
- **Blocklog Backend** (optional for mock/unit tests; required for live end-to-end testing)

### Clone & Build

```bash
git clone https://github.com/blockloglabs/blocklog-mcp.git
cd blocklog-mcp
cargo build
```

---

## Testing & Quality Assurance

Before submitting any code changes or opening a pull request, ensure all the following checks pass cleanly:

### 1. Run Unit and Integration Tests
```bash
cargo test --all-targets
```

### 2. Check Code Formatting
```bash
cargo fmt -- --check
```
To auto-format code:
```bash
cargo fmt
```

### 3. Run Clippy Linter
```bash
cargo clippy --all-targets -- -D warnings
```

---

## Code Guidelines

- **Fail-Closed Security**: Any ambiguity in policy evaluation, receipt validation, or cryptographic hashing must fail closed. Never ignore an error or fall back to an unverified state without explicit configuration.
- **Canonical Serialization**: Ensure all data hashes follow RFC 8785 JSON canonicalization rules with Unicode NFC normalization (`mcp/src/canonical.rs`).
- **Cryptographic Receipts**: Never bypass Ed25519 signature checks or RFC 6962 Merkle tree proofs.
- **Error Handling**: Use structured `AppError` variants (`mcp/src/error.rs`) rather than generic panics. All errors sent to MCP clients must sanitize sensitive internal credentials.
- **Tracing & Logging**: Use the `tracing` crate. Never log plain-text API keys, authorization tokens, or sensitive customer credentials.

---

## Submitting Pull Requests

1. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```
2. **Commit Your Changes**: Follow clear commit messages describing *what* and *why*:
   ```bash
   git commit -m "feat(transport): add keep-alive support for streamable http"
   ```
3. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
4. **Open a PR**: Submit a pull request against `main`. Provide a descriptive overview of changes, rationale, and test verification output.

---

## Reporting Security Issues

Please do **NOT** open public GitHub issues for security vulnerabilities. Instead, refer to [SECURITY.md](SECURITY.md) or email security concerns directly to:

**security@blocklogsecurity.com**
