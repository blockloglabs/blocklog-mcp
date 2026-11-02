use std::collections::BTreeMap;

use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::canonical::{canonical_encode, sha256_hex};
use crate::config::TrustRootConfig;
use crate::crypto::{resolve_public_key, verify_ed25519};
use crate::error::AppError;
use crate::merkle::{leaf_hash, proof_from_hashes, verify_consistency, verify_inclusion};

const ATTACHED_FIELDS: &[&str] = &[
    "merkle_root",
    "merkle_proof",
    "transparency_checkpoint",
    "transparency_proof",
    "witness_attestations",
    "counterparty_attestations",
    "metadata",
    "created_at",
    "updated_at",
];

#[derive(Debug, Clone, Serialize)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub verified: bool,
    pub receipt_id: Option<String>,
    pub verified_at: String,
    pub signature_verified: bool,
    pub cryptographically_verified: bool,
    pub structural_valid: bool,
    pub checks: Vec<VerificationCheck>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub outcome_assessment: Option<Value>,
    pub transparency_assessment: Option<Value>,
}

impl VerificationReport {
    fn new(receipt_id: Option<String>) -> Self {
        Self {
            verified: true,
            receipt_id,
            verified_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            signature_verified: false,
            cryptographically_verified: false,
            structural_valid: true,
            checks: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            outcome_assessment: None,
            transparency_assessment: None,
        }
    }

    fn add_check(&mut self, name: impl Into<String>, passed: bool, detail: impl Into<String>) {
        let name = name.into();
        let detail = detail.into();
        if !passed {
            self.verified = false;
            self.errors.push(format!("{name}: {detail}"));
            if matches!(
                name.as_str(),
                "schema_version"
                    | "required_fields"
                    | "commitments_format"
                    | "execution_commitment_syntax"
                    | "execution_commitment_length"
                    | "outcome_commitment_syntax"
                    | "canonical_hash"
            ) {
                self.structural_valid = false;
            }
        }
        self.checks.push(VerificationCheck {
            name,
            passed,
            detail,
        });
    }

    fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    fn merge_checkpoint(&mut self, other: &Self) {
        for check in &other.checks {
            self.add_check(&check.name, check.passed, &check.detail);
        }
        for warning in &other.warnings {
            self.add_warning(warning);
        }
    }
}

pub struct VerifyOptions<'a> {
    pub public_key: Option<&'a str>,
    pub default_public_key: Option<&'a str>,
    pub trust_roots: &'a BTreeMap<String, TrustRootConfig>,
    pub witness_trust_roots: &'a BTreeMap<String, String>,
    pub counterparty_trust_roots: &'a BTreeMap<String, String>,
    pub require_signature: bool,
    pub require_merkle: bool,
    pub allowed_witness_ids: Option<&'a [String]>,
}

pub fn verify_receipt(receipt: &Value, options: &VerifyOptions<'_>) -> VerificationReport {
    let receipt_id = receipt
        .get("receipt_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let mut report = VerificationReport::new(receipt_id.clone());

    let version = receipt
        .get("version")
        .or_else(|| receipt.get("schema_version"))
        .and_then(Value::as_str);
    match version {
        None => report.add_check("schema_version", false, "Missing version field"),
        Some(version)
            if matches!(
                version,
                "1.0" | "execution/1.0" | "blocklog-verification-v1"
            ) =>
        {
            report.add_check(
                "schema_version",
                true,
                format!("Receipt version '{version}' recognized"),
            );
        }
        Some(version) => report.add_check(
            "schema_version",
            false,
            format!("Unsupported receipt version: {version}"),
        ),
    }

    let required = ["execution_id", "policy", "execution", "commitments"];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|field| receipt.get(*field).is_none())
        .collect();
    if missing.is_empty() {
        report.add_check(
            "required_fields",
            true,
            "All required envelope fields present",
        );
    } else {
        report.add_check(
            "required_fields",
            false,
            format!("Missing required fields: {}", missing.join(", ")),
        );
    }

    match receipt.get("commitments") {
        Some(Value::Object(commitments)) => {
            report.add_check(
                "commitments_format",
                true,
                "Commitments block is a JSON object",
            );
            if let Some(commitment) = commitments
                .get("execution_commitment")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                if commitment.len() == 64 {
                    report.add_check(
                        "execution_commitment_syntax",
                        true,
                        "Execution commitment format valid",
                    );
                    report.add_check(
                        "execution_commitment_length",
                        true,
                        "Execution commitment length valid",
                    );
                } else {
                    report.add_check(
                        "execution_commitment_length",
                        false,
                        format!("Invalid hash length: {}", commitment.len()),
                    );
                }
            }
            if let Some(outcome) = commitments
                .get("outcome_commitment")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                report.add_check(
                    "outcome_commitment_syntax",
                    outcome.len() == 64,
                    if outcome.len() == 64 {
                        "Outcome commitment format valid".to_owned()
                    } else {
                        format!("Invalid outcome hash length: {}", outcome.len())
                    },
                );
            }
        }
        _ => report.add_check(
            "commitments_format",
            false,
            "Commitments block must be a JSON object",
        ),
    }

    let integrity = receipt.get("integrity").unwrap_or(&Value::Null);
    let stored_hash = integrity
        .get("canonical_serialization_hash")
        .or_else(|| receipt.get("canonical_serialization_hash"))
        .and_then(Value::as_str);

    let mut payload_for_verification = receipt.clone();
    if let Some(signing) = payload_for_verification.get_mut("signing") {
        if let Some(object) = signing.as_object_mut() {
            object.remove("signature");
        }
    }
    if let Some(object) = payload_for_verification.as_object_mut() {
        for field in [
            "signature",
            "attestations",
            "counterparty_attestations",
            "witness_attestations",
            "transparency_checkpoint",
            "transparency_proof",
            "merkle_root",
            "merkle_proof",
            "metadata",
            "created_at",
            "updated_at",
        ] {
            object.remove(field);
        }
    }
    let mut payload_without_hash = payload_for_verification.clone();
    if let Some(integrity) = payload_without_hash.get_mut("integrity") {
        if let Some(object) = integrity.as_object_mut() {
            object.remove("canonical_serialization_hash");
        }
    }
    if let Some(object) = payload_without_hash.as_object_mut() {
        object.remove("canonical_serialization_hash");
    }
    let computed_hash = canonical_encode(&payload_without_hash)
        .map(sha256_hex)
        .unwrap_or_default();
    if let Some(stored_hash) = stored_hash {
        let mut working = receipt.clone();
        if let Some(object) = working.as_object_mut() {
            for field in [
                "metadata",
                "created_at",
                "updated_at",
                "transparency_checkpoint",
                "transparency_proof",
                "merkle_root",
                "merkle_proof",
                "witness_attestations",
                "counterparty_attestations",
            ] {
                object.remove(field);
            }
        }
        let full_hash = canonical_encode(&working)
            .map(sha256_hex)
            .unwrap_or_default();
        let matches = stored_hash == computed_hash || stored_hash == full_hash;
        report.add_check(
            "canonical_hash",
            matches,
            if matches {
                "Canonical serialization hash matches payload".to_owned()
            } else {
                format!("Canonical hash mismatch: stored={stored_hash}, computed={computed_hash}")
            },
        );
    } else {
        report.add_warning("Receipt does not contain canonical_serialization_hash");
    }

    let mut signed_artifact = receipt.clone();
    if let Some(object) = signed_artifact.as_object_mut() {
        for field in ATTACHED_FIELDS {
            object.remove(*field);
        }
    }
    let expected_leaf = canonical_encode(&signed_artifact)
        .map(|encoded| hex::encode(leaf_hash(&encoded)))
        .unwrap_or_default();

    let merkle_root = integrity
        .get("merkle_root")
        .or_else(|| receipt.get("merkle_root"))
        .and_then(Value::as_str);
    let merkle_proof = integrity
        .get("merkle_proof")
        .or_else(|| receipt.get("merkle_proof"));
    let transparency_proof = receipt.get("transparency_proof").unwrap_or(&Value::Null);
    let requires_leaf_binding = !transparency_proof.is_null()
        && transparency_proof
            .as_object()
            .is_some_and(|object| !object.is_empty())
        || receipt
            .get("proofs")
            .and_then(|proofs| proofs.get("merkle_inclusion"))
            .and_then(|inclusion| inclusion.get("status"))
            .and_then(Value::as_str)
            == Some("external_bundle");

    match (merkle_proof, merkle_root) {
        (Some(Value::Object(proof)), Some(root)) => {
            let leaf = proof.get("leaf_hash").and_then(Value::as_str);
            let leaf_matches = leaf.is_some_and(|leaf| leaf.eq_ignore_ascii_case(&expected_leaf));
            if leaf.is_none() {
                report.add_check(
                    "receipt_leaf_binding",
                    false,
                    "Merkle proof is missing its leaf hash",
                );
            } else if !leaf_matches {
                if requires_leaf_binding {
                    report.add_check(
                        "receipt_leaf_binding",
                        false,
                        "Merkle leaf does not commit to the signed receipt artifact",
                    );
                } else {
                    report.add_warning(
                        "Legacy Merkle leaf is not bound to the signed artifact; use strict mode for new receipts",
                    );
                }
            } else {
                report.add_check(
                    "receipt_leaf_binding",
                    true,
                    "Merkle leaf commits to the exact signed receipt artifact",
                );
            }
            if leaf_matches || !requires_leaf_binding {
                let leaf_index =
                    proof.get("leaf_index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let tree_size = proof
                    .get("tree_size")
                    .and_then(Value::as_u64)
                    .or_else(|| {
                        receipt
                            .get("transparency_checkpoint")
                            .and_then(|checkpoint| checkpoint.get("tree_size"))
                            .and_then(Value::as_u64)
                    })
                    .unwrap_or(1) as usize;
                let steps = proof_entries(proof, leaf_index, tree_size);
                match (leaf, steps) {
                    (Some(leaf), Ok(steps)) => match verify_inclusion(
                        leaf_index,
                        tree_size,
                        leaf,
                        root,
                        &steps,
                    ) {
                        Ok(true) => report.add_check(
                            "merkle_proof",
                            true,
                            format!(
                                "RFC 6962 Merkle inclusion proof verified against root {}...",
                                root.chars().take(16).collect::<String>()
                            ),
                        ),
                        Ok(false) => report.add_check(
                            "merkle_proof",
                            false,
                            format!(
                                "RFC 6962 Merkle inclusion proof verification failed for root {}...",
                                root.chars().take(16).collect::<String>()
                            ),
                        ),
                        Err(error) => {
                            report.add_check("merkle_proof", false, error.to_string());
                        }
                    },
                    (None, _) => report.add_warning(
                        "Cannot verify Merkle proof without leaf_hash or canonical_hash",
                    ),
                    (_, Err(error)) => report.add_check("merkle_proof", false, error.to_string()),
                }
            }
        }
        _ if options.require_merkle => report.add_check(
            "merkle_proof",
            false,
            "Receipt missing required Merkle proof or root",
        ),
        _ => report.add_warning("No Merkle inclusion proof present to verify"),
    }

    let signing = receipt.get("signing").unwrap_or(&Value::Null);
    let signature = signing
        .get("signature")
        .or_else(|| receipt.get("signature"))
        .and_then(Value::as_str);
    let key_id = signing
        .get("signer_key_id")
        .or_else(|| signing.get("key_id"))
        .and_then(Value::as_str);
    let algorithm = signing
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("ed25519");

    if options.require_signature {
        match signature {
            None => report.add_check("signature", false, "Missing cryptographic signature"),
            Some(signature) => {
                match resolve_public_key(
                    options.public_key,
                    options.default_public_key,
                    key_id,
                    options.trust_roots,
                ) {
                    Ok((public_key, status, root_algorithm)) => {
                        if status.eq_ignore_ascii_case("revoked") {
                            report.add_check(
                                "trust_root_status",
                                false,
                                format!(
                                    "Signing key '{}' has been REVOKED",
                                    key_id.unwrap_or("override")
                                ),
                            );
                        }
                        let algorithm = if root_algorithm.is_empty() {
                            algorithm
                        } else {
                            &root_algorithm
                        };
                        match public_key {
                            None => report.add_check(
                                "signature",
                                false,
                                format!(
                                    "No trusted public key found for key identifier '{}'",
                                    key_id.unwrap_or("")
                                ),
                            ),
                            Some(_public_key) if !algorithm.eq_ignore_ascii_case("ed25519") => {
                                report.add_check(
                                    "signature_algorithm",
                                    false,
                                    format!("Unsupported signing algorithm: {algorithm}"),
                                )
                            }
                            Some(public_key) => match canonical_encode(&payload_for_verification) {
                                Ok(message) => {
                                    match verify_ed25519(&public_key, signature, &message) {
                                        Ok(true) => {
                                            report.signature_verified = true;
                                            report.add_check(
                                                "signature",
                                                true,
                                                format!(
                                                    "Ed25519 signature valid using key '{}'",
                                                    key_id.unwrap_or("override")
                                                ),
                                            );
                                        }
                                        Ok(false) => {
                                            report.signature_verified = false;
                                            report.add_check(
                                                "signature",
                                                false,
                                                "Ed25519 signature verification failed (mismatch)",
                                            );
                                        }
                                        Err(error) => {
                                            report.signature_verified = false;
                                            report.add_check(
                                                "signature",
                                                false,
                                                format!("Signature verification error: {error}"),
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    report.signature_verified = false;
                                    report.add_check(
                                        "signature",
                                        false,
                                        format!("Canonicalization error: {error}"),
                                    );
                                }
                            },
                        }
                    }
                    Err(error) => {
                        report.add_check("signature", false, error.to_string());
                    }
                }
            }
        }
    } else {
        report.verified = false;
        report.add_warning(
            "CRYPTOGRAPHIC SIGNATURE CHECK SKIPPED: This receipt is NOT cryptographically verified. Do NOT use for trust or security decisions.",
        );
        report.add_check(
            "signature",
            false,
            "Signature verification SKIPPED by caller; structural validation only.",
        );
    }

    let checkpoint = receipt
        .get("transparency_checkpoint")
        .or_else(|| transparency_proof.get("checkpoint"));
    let witness_acks = receipt
        .get("witness_attestations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut witness_verified = 0usize;
    let mut checkpoint_present = false;

    if let Some(checkpoint) = checkpoint.filter(|value| value.is_object()) {
        checkpoint_present = true;
        let previous = transparency_proof.get("previous_checkpoint");
        let consistency = transparency_proof
            .get("consistency_proof")
            .and_then(Value::as_array);
        let checkpoint_report = verify_checkpoint(
            checkpoint,
            previous,
            consistency,
            options.default_public_key,
            options.trust_roots,
        );
        report.merge_checkpoint(&checkpoint_report);

        if !transparency_proof.is_null() {
            let proof_root = transparency_proof
                .get("merkle_root")
                .and_then(Value::as_str)
                .unwrap_or("");
            let checkpoint_root = checkpoint
                .get("root_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !proof_root.eq_ignore_ascii_case(checkpoint_root) {
                report.add_check(
                    "transparency_root_binding",
                    false,
                    "Transparency proof root does not match the signed checkpoint root",
                );
            } else if merkle_root.is_some_and(|root| !proof_root.eq_ignore_ascii_case(root)) {
                report.add_check(
                    "transparency_root_binding",
                    false,
                    "Transparency proof root does not match the receipt Merkle root",
                );
            } else {
                report.add_check(
                    "transparency_root_binding",
                    true,
                    "Receipt Merkle root matches the signed checkpoint root",
                );
            }
            let proof_size = transparency_proof.get("tree_size").and_then(Value::as_u64);
            let checkpoint_size = checkpoint.get("tree_size").and_then(Value::as_u64);
            if proof_size != checkpoint_size {
                report.add_check(
                    "transparency_tree_size",
                    false,
                    "Transparency proof tree size does not match the checkpoint",
                );
            } else {
                report.add_check("transparency_tree_size", true, "Tree sizes are consistent");
            }
            if let Some(proof_leaf) = transparency_proof.get("leaf_hash").and_then(Value::as_str) {
                let merkle_leaf = merkle_proof
                    .and_then(|proof| proof.get("leaf_hash"))
                    .and_then(Value::as_str);
                let merkle_index = merkle_proof
                    .and_then(|proof| proof.get("leaf_index"))
                    .and_then(Value::as_u64);
                let proof_index = transparency_proof.get("leaf_index").and_then(Value::as_u64);
                if !proof_leaf.eq_ignore_ascii_case(&expected_leaf)
                    || merkle_leaf.is_some_and(|leaf| !leaf.eq_ignore_ascii_case(&expected_leaf))
                {
                    report.add_check(
                        "transparency_leaf_binding",
                        false,
                        "Transparency proof leaf hash does not match the signed receipt artifact",
                    );
                } else if merkle_index.is_some() && merkle_index != proof_index {
                    report.add_check(
                        "transparency_leaf_binding",
                        false,
                        "Transparency proof leaf index does not match the receipt Merkle proof",
                    );
                } else {
                    report.add_check(
                        "transparency_leaf_binding",
                        true,
                        "Transparency proof and receipt Merkle proof bind the same leaf",
                    );
                }
            }
        }

        for (index, ack) in witness_acks.iter().enumerate() {
            let witness_id = ack.get("witness_id").and_then(Value::as_str).unwrap_or("");
            if options
                .allowed_witness_ids
                .is_some_and(|allowed| !allowed.iter().any(|item| item == witness_id))
            {
                report.add_check(
                    format!("witness_ack_{index}"),
                    false,
                    format!("Witness '{witness_id}' is not in allowed witness list"),
                );
                continue;
            }
            match verify_witness_ack(ack, checkpoint, options.witness_trust_roots) {
                Ok(witness_report) if witness_report.verified => {
                    witness_verified += 1;
                }
                Ok(witness_report) => {
                    report.add_check(
                        format!("witness_ack_{index}"),
                        false,
                        format!("Witness ACK invalid: {:?}", witness_report.errors),
                    );
                }
                Err(error) => report.add_check(
                    format!("witness_ack_{index}"),
                    false,
                    format!("Witness ACK invalid: {error}"),
                ),
            }
        }
    } else if !transparency_proof.is_null() {
        report.add_check(
            "transparency_proof",
            false,
            "Transparency proof is missing its checkpoint",
        );
    }

    report.transparency_assessment = Some(json!({
        "checkpoint_present": checkpoint_present,
        "witness_acks_present": !witness_acks.is_empty(),
        "witness_acks_verified": witness_verified,
        "quorum_established": false,
        "status": if witness_verified > 0 { "WITNESSED" } else if checkpoint_present { "CHECKPOINTED" } else { "UNCHECKPOINTED" },
    }));

    let attestations = receipt
        .get("counterparty_attestations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let outcome = receipt.get("outcome").unwrap_or(&Value::Null);
    let outcome_status = outcome
        .get("status")
        .or_else(|| receipt.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut verified_counterparties = 0usize;
    for (index, attestation) in attestations.iter().enumerate() {
        match verify_counterparty(
            attestation,
            options.counterparty_trust_roots,
            receipt.get("execution_id").and_then(Value::as_str),
            report.receipt_id.as_deref(),
            if outcome_status == "unknown" {
                None
            } else {
                Some(outcome_status)
            },
        ) {
            Ok((true, detail)) => {
                verified_counterparties += 1;
                report.add_check(format!("counterparty_attestation_{index}"), true, detail);
            }
            Ok((false, detail)) => {
                let contradictory = detail.contains("CONTRADICTORY_OUTCOME_ATTESTATION");
                report.add_check(format!("counterparty_attestation_{index}"), false, &detail);
                if contradictory {
                    report.verified = false;
                    report
                        .errors
                        .push(format!("counterparty_attestation_{index}: {detail}"));
                }
            }
            Err(error) => {
                report.add_check(
                    format!("counterparty_attestation_{index}"),
                    false,
                    error.to_string(),
                );
            }
        }
    }

    let outcome_source = if verified_counterparties > 0 {
        "counterparty_attested"
    } else {
        outcome
            .get("source")
            .or_else(|| receipt.get("outcome_source"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    };
    let confidence = match outcome_source {
        "counterparty_attested" => "MAXIMAL",
        "adapter_verified" => "HIGH",
        _ => "LOW",
    };
    report.outcome_assessment = Some(json!({
        "claimed_status": outcome_status,
        "source_type": outcome_source,
        "real_world_verified": matches!(outcome_source, "adapter_verified" | "counterparty_attested"),
        "confidence": confidence,
        "counterparty_attestations_verified": verified_counterparties,
    }));
    if outcome_source == "agent_reported" {
        report.add_warning(
            "Outcome is self-reported by the agent (source=agent_reported). Cryptographic receipt proves authorization, but does NOT prove physical or financial outcome.",
        );
    } else if matches!(outcome_source, "adapter_verified" | "counterparty_attested") {
        report.add_check(
            "outcome_assurance",
            true,
            format!(
                "Outcome backed by independent evidence (source={outcome_source}, confidence={confidence})"
            ),
        );
    }

    report.cryptographically_verified = report.verified && report.signature_verified;
    report
}

fn proof_entries(
    proof: &Map<String, Value>,
    leaf_index: usize,
    tree_size: usize,
) -> Result<Vec<Value>, AppError> {
    if let Some(steps) = proof.get("steps").and_then(Value::as_array) {
        if !steps.is_empty() {
            return Ok(steps.clone());
        }
    }
    if let Some(hashes) = proof.get("sibling_hashes").and_then(Value::as_array) {
        if hashes.iter().all(Value::is_string) {
            let hashes: Vec<String> = hashes
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            return proof_from_hashes(leaf_index, tree_size, &hashes);
        }
        if hashes.iter().all(Value::is_object) {
            return Ok(hashes.clone());
        }
    }
    Ok(Vec::new())
}

fn verify_checkpoint(
    checkpoint: &Value,
    previous_checkpoint: Option<&Value>,
    consistency_proof: Option<&Vec<Value>>,
    default_public_key: Option<&str>,
    trust_roots: &BTreeMap<String, TrustRootConfig>,
) -> VerificationReport {
    let mut report = VerificationReport::new(None);
    let protocol = checkpoint
        .get("protocol_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    if protocol != "checkpoint/1.0" {
        report.add_check(
            "checkpoint_version",
            false,
            format!("Unsupported checkpoint protocol: {protocol}"),
        );
        return report;
    }
    report.add_check(
        "checkpoint_version",
        true,
        "Checkpoint protocol version 'checkpoint/1.0' recognized",
    );

    let tree_size = checkpoint.get("tree_size").and_then(Value::as_u64);
    let root_hash = checkpoint
        .get("root_hash")
        .and_then(Value::as_str)
        .unwrap_or("");
    let log_id = checkpoint.get("log_id").and_then(Value::as_str);
    if tree_size.is_none() || root_hash.is_empty() || log_id.is_none() {
        report.add_check(
            "checkpoint_structure",
            false,
            "Missing log_id, tree_size, or root_hash",
        );
        return report;
    }
    report.add_check(
        "checkpoint_structure",
        true,
        format!(
            "Valid checkpoint structure for log '{}' (tree_size={})",
            log_id.unwrap_or(""),
            tree_size.unwrap_or(0)
        ),
    );

    let signing = checkpoint.get("signing").unwrap_or(&Value::Null);
    let key_id = signing
        .get("signer_key_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let signature = signing
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or("");
    if key_id.is_empty() || signature.is_empty() {
        report.add_check(
            "checkpoint_signature",
            false,
            "Missing signer_key_id or signature",
        );
        return report;
    }

    let (public_key, status) = match trust_roots.get(key_id) {
        Some(root) => (Some(root.public_key.as_str()), root.status.as_str()),
        None => (default_public_key, "active"),
    };
    if status.eq_ignore_ascii_case("revoked") {
        report.add_check(
            "checkpoint_key_status",
            false,
            format!("Signing key '{key_id}' is REVOKED"),
        );
        return report;
    }
    let Some(public_key) = public_key else {
        report.add_check(
            "checkpoint_signature",
            false,
            format!("Untrusted signer key '{key_id}'"),
        );
        return report;
    };
    let message = checkpoint_message(checkpoint, key_id);
    match message.and_then(|message| verify_ed25519(public_key, signature, &message)) {
        Ok(true) => report.add_check(
            "checkpoint_signature",
            true,
            format!("Checkpoint signature valid under key '{key_id}'"),
        ),
        Ok(false) => {
            report.add_check(
                "checkpoint_signature",
                false,
                "Checkpoint signature verification failed",
            );
            return report;
        }
        Err(error) => {
            report.add_check("checkpoint_signature", false, error.to_string());
            return report;
        }
    }

    if let Some(previous) = previous_checkpoint.filter(|value| value.is_object()) {
        let previous_size = previous
            .get("tree_size")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let current_size = tree_size.unwrap_or(0);
        let previous_root = previous
            .get("root_hash")
            .and_then(Value::as_str)
            .unwrap_or("");
        if current_size < previous_size {
            report.add_check(
                "tree_monotonicity",
                false,
                format!("Tree size rollback: {current_size} < previous {previous_size}"),
            );
            return report;
        }
        if current_size == previous_size {
            if !root_hash.eq_ignore_ascii_case(previous_root) {
                report.add_check(
                    "anti_fork",
                    false,
                    format!("Fork detected: identical size {current_size} has conflicting roots"),
                );
            } else {
                report.add_check(
                    "anti_fork",
                    true,
                    "Checkpoint matches previous root identically",
                );
            }
        } else {
            let proof: Vec<String> = consistency_proof
                .map(|proof| {
                    proof
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if proof.is_empty() {
                report.add_check(
                    "consistency_proof",
                    false,
                    "Missing required consistency proof for growing tree",
                );
                return report;
            }
            match verify_consistency(previous_size as usize, current_size as usize, previous_root, root_hash, &proof) {
                Ok(true) => report.add_check(
                    "consistency_proof",
                    true,
                    format!(
                        "Consistency verified from size {previous_size} to {current_size}"
                    ),
                ),
                Ok(false) => report.add_check(
                    "consistency_proof",
                    false,
                    format!(
                        "RFC 6962 consistency proof failed between size {previous_size} and {current_size}"
                    ),
                ),
                Err(error) => report.add_check("consistency_proof", false, error.to_string()),
            }
        }
    } else {
        report.add_warning(
            "No previous trusted checkpoint provided: verified signature only, not history continuity",
        );
    }
    report
}

fn checkpoint_message(checkpoint: &Value, signer_key_id: &str) -> Result<Vec<u8>, AppError> {
    let payload = json!({
        "protocol_version": checkpoint.get("protocol_version").and_then(Value::as_str).unwrap_or("checkpoint/1.0"),
        "log_id": checkpoint.get("log_id").cloned().unwrap_or(Value::Null),
        "tree_size": checkpoint.get("tree_size").cloned().unwrap_or(Value::Null),
        "root_hash": checkpoint.get("root_hash").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase(),
        "timestamp": checkpoint.get("timestamp").cloned().unwrap_or(Value::Null),
        "checkpoint_id": checkpoint.get("checkpoint_id").cloned().unwrap_or(Value::Null),
        "previous_root_hash": checkpoint.get("previous_root_hash").cloned().unwrap_or(Value::Null),
        "signer_key_id": signer_key_id,
        "algorithm": checkpoint.get("signing").and_then(|signing| signing.get("algorithm")).and_then(Value::as_str).unwrap_or("ed25519"),
    });
    canonical_encode(&payload).map_err(|error| AppError::Crypto(error.to_string()))
}

fn verify_witness_ack(
    ack: &Value,
    checkpoint: &Value,
    witness_trust_roots: &BTreeMap<String, String>,
) -> Result<VerificationReport, AppError> {
    let mut report = VerificationReport::new(None);
    let log_id = ack.get("log_id").and_then(Value::as_str).unwrap_or("");
    let tree_size = ack.get("tree_size").and_then(Value::as_u64).unwrap_or(0);
    let root_hash = ack.get("root_hash").and_then(Value::as_str).unwrap_or("");
    if Some(log_id) != checkpoint.get("log_id").and_then(Value::as_str) {
        report.add_check("witness_log_binding", false, "Log ID mismatch");
    }
    if Some(tree_size) != checkpoint.get("tree_size").and_then(Value::as_u64) {
        report.add_check("witness_size_binding", false, "Tree size mismatch");
    }
    if !root_hash.eq_ignore_ascii_case(
        checkpoint
            .get("root_hash")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        report.add_check("witness_root_binding", false, "Root hash mismatch");
    }
    let witness_key_id = ack
        .get("witness_key_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(public_key) = witness_trust_roots.get(witness_key_id) else {
        report.add_check(
            "witness_trust_root",
            false,
            format!("Witness key '{witness_key_id}' not in trusted witness roots"),
        );
        return Ok(report);
    };
    let signature = ack.get("signature").and_then(Value::as_str).unwrap_or("");
    let message = witness_message(ack)?;
    match verify_ed25519(public_key, signature, &message) {
        Ok(true) => report.add_check(
            "witness_signature",
            true,
            format!(
                "Witness acknowledgement valid from witness '{}'",
                ack.get("witness_id").and_then(Value::as_str).unwrap_or("")
            ),
        ),
        Ok(false) => report.add_check(
            "witness_signature",
            false,
            "Witness acknowledgement signature verification failed",
        ),
        Err(error) => report.add_check("witness_signature", false, error.to_string()),
    }
    Ok(report)
}

fn witness_message(ack: &Value) -> Result<Vec<u8>, AppError> {
    let payload = json!({
        "protocol_version": ack.get("protocol_version").and_then(Value::as_str).unwrap_or("witness-ack/1.0"),
        "witness_id": ack.get("witness_id").and_then(Value::as_str).unwrap_or(""),
        "log_id": ack.get("log_id").and_then(Value::as_str).unwrap_or(""),
        "tree_size": ack.get("tree_size").cloned().unwrap_or(Value::Null),
        "root_hash": ack.get("root_hash").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase(),
        "checkpoint_id": ack.get("checkpoint_id").and_then(Value::as_str).unwrap_or(""),
        "acknowledged_at": ack.get("acknowledged_at").and_then(Value::as_str).unwrap_or(""),
        "witness_key_id": ack.get("witness_key_id").and_then(Value::as_str).unwrap_or(""),
    });
    canonical_encode(&payload).map_err(|error| AppError::Crypto(error.to_string()))
}

fn verify_counterparty(
    attestation: &Value,
    trust_roots: &BTreeMap<String, String>,
    expected_execution_id: Option<&str>,
    expected_receipt_id: Option<&str>,
    expected_outcome: Option<&str>,
) -> Result<(bool, String), AppError> {
    let protocol = attestation
        .get("protocol_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    if protocol != "attestation/1.0" {
        return Ok((
            false,
            format!("Unsupported attestation protocol version: {protocol}"),
        ));
    }
    let signing = attestation.get("signing").unwrap_or(&Value::Null);
    let signature = signing
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or("");
    if signature.is_empty() {
        return Ok((false, "Attestation signature is missing".to_owned()));
    }
    if let Some(expected) = expected_execution_id {
        if attestation.get("execution_id").and_then(Value::as_str) != Some(expected) {
            return Ok((false, format!("Execution ID mismatch: expected {expected}")));
        }
    }
    if let Some(expected) = expected_receipt_id {
        if attestation.get("receipt_id").and_then(Value::as_str) != Some(expected) {
            return Ok((false, format!("Receipt ID mismatch: expected {expected}")));
        }
    }
    let assertion = attestation.get("assertion").unwrap_or(&Value::Null);
    if let Some(expected) = expected_outcome {
        let actual = assertion
            .get("outcome_status")
            .and_then(Value::as_str)
            .unwrap_or("");
        if actual != expected {
            return Ok((
                false,
                format!(
                    "CONTRADICTORY_OUTCOME_ATTESTATION: receipt claims '{expected}' but attestation asserts '{actual}'"
                ),
            ));
        }
    }
    let key_id = signing
        .get("counterparty_key_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(public_key) = trust_roots.get(key_id) else {
        return Ok((
            false,
            format!("Counterparty key '{key_id}' not found in trusted counterparty roots"),
        ));
    };
    let message = counterparty_message(attestation)?;
    match verify_ed25519(public_key, signature, &message) {
        Ok(true) => Ok((
            true,
            format!(
                "Valid attestation from {} ({})",
                attestation
                    .get("counterparty")
                    .and_then(|value| value.get("organization_name"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown counterparty"),
                assertion
                    .get("outcome_status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
        )),
        Ok(false) => Ok((
            false,
            "Counterparty signature verification failed".to_owned(),
        )),
        Err(error) => Ok((false, error.to_string())),
    }
}

fn counterparty_message(attestation: &Value) -> Result<Vec<u8>, AppError> {
    let signing = attestation.get("signing").unwrap_or(&Value::Null);
    let payload = json!({
        "protocol_version": attestation.get("protocol_version").and_then(Value::as_str).unwrap_or("attestation/1.0"),
        "attestation_id": attestation.get("attestation_id").and_then(Value::as_str).unwrap_or(""),
        "execution_id": attestation.get("execution_id").and_then(Value::as_str).unwrap_or(""),
        "receipt_id": attestation.get("receipt_id").and_then(Value::as_str).unwrap_or(""),
        "request_fingerprint": attestation.get("request_fingerprint").and_then(Value::as_str).unwrap_or(""),
        "counterparty": attestation.get("counterparty").cloned().unwrap_or_else(|| json!({})),
        "assertion": attestation.get("assertion").cloned().unwrap_or_else(|| json!({})),
        "timestamp": attestation.get("timestamp").and_then(Value::as_str).unwrap_or(""),
        "counterparty_key_id": signing.get("counterparty_key_id").and_then(Value::as_str).unwrap_or(""),
        "algorithm": signing.get("algorithm").and_then(Value::as_str).unwrap_or("ed25519"),
    });
    canonical_encode(&payload).map_err(|error| AppError::Crypto(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_receipt() -> (Value, String) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let receipt_id = "rcpt_test_1".to_owned();
        let mut receipt = json!({
            "version": "1.0",
            "receipt_id": receipt_id,
            "execution_id": "exec_test_1",
            "policy": {"policy_id": "pol_1"},
            "execution": {"action_type": "payment.create"},
            "commitments": {
                "execution_commitment": "a".repeat(64),
                "outcome_commitment": "b".repeat(64)
            },
            "integrity": {},
            "signing": {
                "signer_key_id": "test-key",
                "algorithm": "ed25519"
            },
            "outcome": {"status": "SUCCEEDED", "source": "adapter_verified"}
        });

        let mut signing_payload = receipt.clone();
        if let Some(signing) = signing_payload.get_mut("signing") {
            signing
                .as_object_mut()
                .map(|object| object.remove("signature"));
        }
        for field in ATTACHED_FIELDS {
            signing_payload
                .as_object_mut()
                .map(|object| object.remove(*field));
        }
        let mut hash_payload = signing_payload.clone();
        hash_payload
            .as_object_mut()
            .map(|object| object.remove("canonical_serialization_hash"));
        let canonical_hash = sha256_hex(canonical_encode(&hash_payload).expect("canonical"));
        receipt["integrity"] = json!({"canonical_serialization_hash": canonical_hash});

        let signature = signing_key.sign(&canonical_encode(&receipt).expect("canonical"));
        receipt["signing"]["signature"] = json!(hex::encode(signature.to_bytes()));

        let expected_leaf = hex::encode(leaf_hash(&canonical_encode(&receipt).expect("canonical")));
        receipt["merkle_root"] = json!(expected_leaf);
        receipt["merkle_proof"] = json!({
            "leaf_index": 0,
            "tree_size": 1,
            "leaf_hash": expected_leaf,
            "sibling_hashes": [],
        });
        (receipt, public_key)
    }

    #[test]
    fn verifies_valid_signed_receipt() {
        let (receipt, public_key) = signed_receipt();
        let mut trust_roots = BTreeMap::new();
        trust_roots.insert(
            "test-key".to_owned(),
            TrustRootConfig {
                public_key,
                status: "active".to_owned(),
                algorithm: "ed25519".to_owned(),
            },
        );
        let options = VerifyOptions {
            public_key: None,
            default_public_key: None,
            trust_roots: &trust_roots,
            witness_trust_roots: &BTreeMap::new(),
            counterparty_trust_roots: &BTreeMap::new(),
            require_signature: true,
            require_merkle: true,
            allowed_witness_ids: None,
        };
        let report = verify_receipt(&receipt, &options);
        assert!(report.verified, "errors: {:?}", report.errors);
        assert!(report.signature_verified);
        assert!(report.cryptographically_verified);
    }

    #[test]
    fn verifies_reference_witnessed_receipt() {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../verifier/examples/witnessed_receipt.json"
        ))
        .expect("fixture");
        let signing_roots: Vec<Value> =
            serde_json::from_str(include_str!("../../../verifier/examples/trust_roots.json"))
                .expect("signing roots");
        let witness_roots: BTreeMap<String, String> = serde_json::from_str(include_str!(
            "../../../verifier/examples/witness_roots.json"
        ))
        .expect("witness roots");
        let counterparty_roots: BTreeMap<String, String> = serde_json::from_str(include_str!(
            "../../../verifier/examples/counterparty_roots.json"
        ))
        .expect("counterparty roots");
        let mut trust_roots = BTreeMap::new();
        for root in signing_roots {
            let id = root["key_id"].as_str().expect("key id").to_owned();
            trust_roots.insert(
                id,
                TrustRootConfig {
                    public_key: root["public_key"].as_str().expect("public key").to_owned(),
                    status: root["status"].as_str().unwrap_or("active").to_owned(),
                    algorithm: root["algorithm"].as_str().unwrap_or("ed25519").to_owned(),
                },
            );
        }
        let options = VerifyOptions {
            public_key: None,
            default_public_key: None,
            trust_roots: &trust_roots,
            witness_trust_roots: &witness_roots,
            counterparty_trust_roots: &counterparty_roots,
            require_signature: true,
            require_merkle: true,
            allowed_witness_ids: None,
        };
        let report = verify_receipt(&receipt, &options);
        assert!(report.verified, "errors: {:?}", report.errors);
        assert!(report.signature_verified);
        assert!(report.cryptographically_verified);
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "checkpoint_signature" && check.passed));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "counterparty_attestation_0" && check.passed));
    }

    #[test]
    fn rejects_tampered_receipt() {
        let (mut receipt, public_key) = signed_receipt();
        receipt["execution_id"] = json!("exec_attacker");
        let mut trust_roots = BTreeMap::new();
        trust_roots.insert(
            "test-key".to_owned(),
            TrustRootConfig {
                public_key,
                status: "active".to_owned(),
                algorithm: "ed25519".to_owned(),
            },
        );
        let options = VerifyOptions {
            public_key: None,
            default_public_key: None,
            trust_roots: &trust_roots,
            witness_trust_roots: &BTreeMap::new(),
            counterparty_trust_roots: &BTreeMap::new(),
            require_signature: true,
            require_merkle: true,
            allowed_witness_ids: None,
        };
        let report = verify_receipt(&receipt, &options);
        assert!(!report.verified);
        assert!(!report.signature_verified);
    }
}
