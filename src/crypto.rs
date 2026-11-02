use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::config::TrustRootConfig;
use crate::error::{AppError, AppResult};

pub fn decode_bytes(value: &str) -> AppResult<Vec<u8>> {
    let clean = value.trim();
    let clean = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
        .unwrap_or(clean);

    if (clean.len() == 64 || clean.len() == 128)
        && clean.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return hex::decode(clean)
            .map_err(|_| AppError::Crypto("invalid hexadecimal cryptographic value".to_owned()));
    }

    if clean.len() % 4 == 1 {
        return Err(AppError::Crypto(
            "invalid base64 cryptographic value".to_owned(),
        ));
    }
    let padding = (4 - clean.len() % 4) % 4;
    let padded = format!("{clean}{}", "=".repeat(padding));
    URL_SAFE
        .decode(&padded)
        .or_else(|_| STANDARD.decode(&padded))
        .map_err(|_| AppError::Crypto("invalid base64 cryptographic value".to_owned()))
}

pub fn verify_ed25519(public_key: &str, signature: &str, message: &[u8]) -> AppResult<bool> {
    let public_key_bytes = decode_bytes(public_key)?;
    let signature_bytes = decode_bytes(signature)?;
    if public_key_bytes.len() != 32 {
        return Err(AppError::Crypto(format!(
            "invalid Ed25519 public key length: {} bytes (expected 32)",
            public_key_bytes.len()
        )));
    }
    if signature_bytes.len() != 64 {
        return Err(AppError::Crypto(format!(
            "invalid Ed25519 signature length: {} bytes (expected 64)",
            signature_bytes.len()
        )));
    }
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("invalid Ed25519 public key".to_owned()))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("invalid Ed25519 signature".to_owned()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| AppError::Crypto("invalid Ed25519 public key".to_owned()))?;
    let signature = Signature::from_bytes(&signature_array);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn resolve_public_key(
    explicit: Option<&str>,
    default_public_key: Option<&str>,
    key_id: Option<&str>,
    trust_roots: &std::collections::BTreeMap<String, TrustRootConfig>,
) -> AppResult<(Option<String>, String, String)> {
    if let Some(key) = explicit.filter(|key| !key.trim().is_empty()) {
        return Ok((
            Some(key.to_owned()),
            "active".to_owned(),
            "ed25519".to_owned(),
        ));
    }
    if let Some(key_id) = key_id {
        if let Some(root) = trust_roots.get(key_id) {
            return Ok((
                Some(root.public_key.clone()),
                root.status.clone(),
                root.algorithm.clone(),
            ));
        }
    }
    Ok((
        default_public_key.map(ToOwned::to_owned),
        "active".to_owned(),
        "ed25519".to_owned(),
    ))
}
