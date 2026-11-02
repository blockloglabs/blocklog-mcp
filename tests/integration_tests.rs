use blocklog_mcp::args::*;
use blocklog_mcp::canonical::{canonical_encode, nfc, sha256_hex};
use blocklog_mcp::config::{Config, LogFormat, Mode, Secret, Transport, TrustRootConfig};
use blocklog_mcp::crypto::verify_ed25519;
use blocklog_mcp::merkle::{leaf_hash, tree_hash, verify_consistency, verify_inclusion};
use blocklog_mcp::server::BlocklogMcpServer;
use blocklog_mcp::verifier::{verify_receipt, VerifyOptions};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;

fn test_config() -> Config {
    Config {
        backend_url: "http://127.0.0.1:8000".to_owned(),
        api_key: Some(Secret::new("test-key-secret")),
        mode: Mode::Enforce,
        transport: Transport::Stdio,
        http_bind: "127.0.0.1:8080".parse().unwrap(),
        http_path: "/mcp".to_owned(),
        allowed_hosts: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
        allowed_origins: vec![],
        request_timeout: std::time::Duration::from_secs(15),
        max_argument_bytes: 1024 * 1024,
        max_backend_response_bytes: 8 * 1024 * 1024,
        receipt_public_key: None,
        trust_roots: BTreeMap::new(),
        witness_trust_roots: BTreeMap::new(),
        counterparty_trust_roots: BTreeMap::new(),
        webhook_hosts: std::collections::HashSet::new(),
        allow_insecure_webhooks: false,
        allow_insecure_backend: true,
        log_format: LogFormat::Compact,
    }
}

#[tokio::test]
async fn test_server_creation() {
    let config = test_config();
    let server = BlocklogMcpServer::new(config);
    assert!(
        server.is_ok(),
        "Server should initialize cleanly with valid config"
    );
    let server = server.unwrap();
    assert_eq!(server.config().mode, Mode::Enforce);
    assert_eq!(server.config().transport, Transport::Stdio);
}

#[test]
fn test_action_args_normalization_and_hash() {
    let args = ActionArgs {
        processor: " stripe ".to_owned(),
        action_type: " payment.create ".to_owned(),
        amount_minor: 5000,
        currency: "usd".to_owned(),
        subject_reference: " ord_12345 ".to_owned(),
        destination: Some(" acct_abc ".to_owned()),
        transaction_reference: None,
        context: None,
        idempotency_key: Some("idem_key_12345678".to_owned()),
        trace_id: None,
        session_id: None,
        workflow_id: None,
        integration: None,
    };

    let normalized = args.normalized().expect("normalization should succeed");
    assert_eq!(normalized.processor, "stripe");
    assert_eq!(normalized.action_type, "payment.create");
    assert_eq!(normalized.currency, "USD");
    assert_eq!(normalized.subject_reference, "ord_12345");
    assert_eq!(normalized.destination.as_deref(), Some("acct_abc"));

    let hash = normalized
        .args_hash()
        .expect("hash derivation should succeed");
    assert_eq!(hash.len(), 64, "SHA-256 hex string should be 64 characters");
}

#[test]
fn test_action_args_validation_rejects_invalid_currency() {
    let args = ActionArgs {
        processor: "stripe".to_owned(),
        action_type: "payment.create".to_owned(),
        amount_minor: 100,
        currency: "US".to_owned(), // Too short (< 3 chars)
        subject_reference: "ord_1".to_owned(),
        destination: None,
        transaction_reference: None,
        context: None,
        idempotency_key: None,
        trace_id: None,
        session_id: None,
        workflow_id: None,
        integration: None,
    };
    assert!(args.normalized().is_err());
}

#[test]
fn test_canonical_encoding_determinism() {
    let obj1 = json!({
        "b": 2,
        "a": 1,
        "nested": {
            "z": "end",
            "m": "mid"
        }
    });
    let obj2 = json!({
        "nested": {
            "m": "mid",
            "z": "end"
        },
        "a": 1,
        "b": 2
    });

    let enc1 = canonical_encode(&obj1).expect("encode 1");
    let enc2 = canonical_encode(&obj2).expect("encode 2");
    assert_eq!(
        enc1, enc2,
        "Canonical encoding must be independent of key insertion order"
    );
}

#[test]
fn test_nfc_normalization() {
    // "e" followed by combining acute accent U+0301 vs precomposed "é" U+00E9
    let decomposed = "e\u{0301}";
    let composed = "\u{00E9}";
    assert_eq!(nfc(decomposed), nfc(composed));
}

#[test]
fn test_merkle_tree_rfc6962() {
    let leaf1 = leaf_hash(b"item-1");
    let leaf2 = leaf_hash(b"item-2");
    let leaves = vec![leaf1, leaf2];
    let root = tree_hash(&leaves);
    let root_hex = hex::encode(root);

    let proof = vec![json!({
        "position": "right",
        "hash": hex::encode(leaf2)
    })];

    let verified = verify_inclusion(0, 2, &hex::encode(leaf1), &root_hex, &proof);
    assert!(verified.unwrap(), "Leaf 0 inclusion proof should verify");

    // Negative case: wrong root
    let bogus_root = hex::encode([0u8; 32]);
    let failed = verify_inclusion(0, 2, &hex::encode(leaf1), &bogus_root, &proof);
    assert!(
        !failed.unwrap(),
        "Bogus root must fail inclusion verification"
    );
}

#[test]
fn test_merkle_consistency_verification() {
    let leaves = (0..4)
        .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
        .collect::<Vec<_>>();
    let root_size_2 = tree_hash(&leaves[..2]);
    let root_size_4 = tree_hash(&leaves);

    // Consistency proof between size 2 and size 4: sibling is node_hash(leaf2, leaf3)
    let sibling = blocklog_mcp::merkle::node_hash(&leaves[2], &leaves[3]);
    let proof = vec![hex::encode(sibling)];

    let consistent = verify_consistency(
        2,
        4,
        &hex::encode(root_size_2),
        &hex::encode(root_size_4),
        &proof,
    );
    assert!(
        consistent.unwrap(),
        "Consistency proof between tree size 2 and 4 should pass"
    );
}

#[test]
fn test_ed25519_receipt_verification_lifecycle() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    let message = b"sample-authenticated-receipt-payload";
    let signature = signing_key.sign(message);
    let signature_hex = hex::encode(signature.to_bytes());

    let valid =
        verify_ed25519(&public_key_hex, &signature_hex, message).expect("verification result");
    assert!(valid, "Valid Ed25519 signature should pass");

    let tampered_message = b"tampered-payload";
    let invalid = verify_ed25519(&public_key_hex, &signature_hex, tampered_message)
        .expect("verification result");
    assert!(!invalid, "Tampered payload must fail Ed25519 verification");
}

#[test]
fn test_full_receipt_verification_with_trust_root() {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let receipt_id = "rcpt_mcp_test_888";
    let mut receipt = json!({
        "version": "1.0",
        "receipt_id": receipt_id,
        "execution_id": "exec_mcp_test_888",
        "policy": {"policy_id": "pol_p1"},
        "execution": {"action_type": "transfer.send"},
        "commitments": {
            "execution_commitment": "1".repeat(64),
            "outcome_commitment": "2".repeat(64)
        },
        "integrity": {},
        "signing": {
            "signer_key_id": "root-key-alpha",
            "algorithm": "ed25519"
        },
        "outcome": {"status": "SUCCEEDED", "source": "adapter_verified"}
    });

    let mut payload = receipt.clone();
    if let Some(s) = payload.get_mut("signing") {
        s.as_object_mut().unwrap().remove("signature");
    }
    let canonical = canonical_encode(&payload).unwrap();
    let canon_hash = sha256_hex(&canonical);
    receipt["integrity"]["canonical_serialization_hash"] = json!(canon_hash);

    let signed_msg = canonical_encode(&receipt).unwrap();
    let sig = signing_key.sign(&signed_msg);
    receipt["signing"]["signature"] = json!(hex::encode(sig.to_bytes()));

    let leaf = hex::encode(leaf_hash(&signed_msg));
    receipt["merkle_root"] = json!(leaf);
    receipt["merkle_proof"] = json!({
        "leaf_index": 0,
        "tree_size": 1,
        "leaf_hash": leaf,
        "sibling_hashes": []
    });

    let mut roots = BTreeMap::new();
    roots.insert(
        "root-key-alpha".to_owned(),
        TrustRootConfig {
            public_key: public_key_hex,
            status: "active".to_owned(),
            algorithm: "ed25519".to_owned(),
        },
    );

    let options = VerifyOptions {
        public_key: None,
        default_public_key: None,
        trust_roots: &roots,
        witness_trust_roots: &BTreeMap::new(),
        counterparty_trust_roots: &BTreeMap::new(),
        require_signature: true,
        require_merkle: true,
        allowed_witness_ids: None,
    };

    let report = verify_receipt(&receipt, &options);
    assert!(
        report.verified,
        "Receipt verification should pass: {:?}",
        report.errors
    );
    assert!(report.signature_verified);
    assert!(report.cryptographically_verified);
    assert_eq!(report.receipt_id.as_deref(), Some(receipt_id));
}
