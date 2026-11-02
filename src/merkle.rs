use serde_json::Value;

use crate::canonical::sha256_bytes;
use crate::error::{AppError, AppResult};

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(data.len() + 1);
    payload.push(0x00);
    payload.extend_from_slice(data);
    sha256_bytes(payload)
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x01);
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    sha256_bytes(payload)
}

fn split_index(size: usize) -> usize {
    if size < 2 {
        return 0;
    }
    1usize << ((size - 1).ilog2())
}

pub fn tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256_bytes([]),
        1 => leaves[0],
        size => {
            let split = split_index(size);
            node_hash(&tree_hash(&leaves[..split]), &tree_hash(&leaves[split..]))
        }
    }
}

pub fn expected_directions(mut index: usize, mut size: usize) -> Vec<&'static str> {
    let mut directions = Vec::new();
    while size > 1 {
        let split = split_index(size);
        if index < split {
            directions.push("right");
            size = split;
        } else {
            directions.push("left");
            index -= split;
            size -= split;
        }
    }
    directions
}

pub fn verify_inclusion(
    leaf_index: usize,
    tree_size: usize,
    leaf_hash: &str,
    root_hash: &str,
    proof: &[Value],
) -> AppResult<bool> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Ok(false);
    }
    let current = parse_hash(leaf_hash)?;
    let expected_root = parse_hash(root_hash)?;
    if tree_size == 1 {
        return Ok(proof.is_empty() && current == expected_root);
    }
    let expected = expected_directions(leaf_index, tree_size);
    if proof.len() != expected.len() {
        return Ok(false);
    }
    let mut current = current;
    for (index, step) in proof.iter().enumerate() {
        let position = step
            .get("position")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Verification("Merkle proof step is missing position".to_owned())
            })?;
        let hash = step.get("hash").and_then(Value::as_str).ok_or_else(|| {
            AppError::Verification("Merkle proof step is missing hash".to_owned())
        })?;
        if position != expected[index] {
            return Ok(false);
        }
        let sibling = parse_hash(hash)?;
        current = match position {
            "right" => node_hash(&current, &sibling),
            "left" => node_hash(&sibling, &current),
            _ => return Ok(false),
        };
    }
    Ok(current == expected_root)
}

pub fn proof_from_hashes(
    leaf_index: usize,
    tree_size: usize,
    hashes: &[String],
) -> AppResult<Vec<Value>> {
    let directions = expected_directions(leaf_index, tree_size);
    if hashes.len() != directions.len() {
        return Err(AppError::Verification(format!(
            "Merkle proof has {} hashes but {} are required",
            hashes.len(),
            directions.len()
        )));
    }
    Ok(directions
        .into_iter()
        .zip(hashes)
        .map(|(position, hash)| serde_json::json!({"position": position, "hash": hash}))
        .collect())
}

pub fn verify_consistency(
    previous_size: usize,
    size: usize,
    previous_root: &str,
    root: &str,
    proof: &[String],
) -> AppResult<bool> {
    let previous_root = parse_hash(previous_root)?;
    let root = parse_hash(root)?;
    if previous_size == size {
        return Ok(proof.is_empty() && previous_root == root);
    }
    if previous_size < 1 || previous_size >= size || proof.is_empty() {
        return Ok(false);
    }
    let proof = proof
        .iter()
        .map(|value| parse_hash(value))
        .collect::<AppResult<Vec<_>>>()?;

    let mut node_previous;
    let mut node_current;
    let nodes;
    if previous_size.is_power_of_two() {
        node_previous = previous_root;
        node_current = previous_root;
        nodes = proof.as_slice();
    } else {
        node_previous = proof[0];
        node_current = proof[0];
        nodes = &proof[1..];
    }

    let mut previous_index = previous_size - 1;
    let mut current_index = size - 1;
    while previous_index & 1 == 1 {
        previous_index >>= 1;
        current_index >>= 1;
    }

    for sibling in nodes {
        if current_index == 0 {
            return Ok(false);
        }
        if previous_index & 1 == 1 || previous_index == current_index {
            node_previous = node_hash(sibling, &node_previous);
            node_current = node_hash(sibling, &node_current);
            while previous_index & 1 == 0 && previous_index != 0 {
                previous_index >>= 1;
                current_index >>= 1;
            }
        } else {
            node_current = node_hash(&node_current, sibling);
        }
        previous_index >>= 1;
        current_index >>= 1;
    }

    Ok(node_previous == previous_root && node_current == root && current_index == 0)
}

pub fn parse_hash(value: &str) -> AppResult<[u8; 32]> {
    let bytes = hex::decode(value.trim()).map_err(|_| {
        AppError::Verification(format!("invalid Merkle hash '{}'", truncate(value)))
    })?;
    bytes.try_into().map_err(|_| {
        AppError::Verification(format!("Merkle hash '{}' is not 32 bytes", truncate(value)))
    })
}

fn truncate(value: &str) -> String {
    value.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_leaves(values: &[&str]) -> Vec<[u8; 32]> {
        values
            .iter()
            .map(|value| leaf_hash(value.as_bytes()))
            .collect()
    }

    #[test]
    fn verifies_rfc6962_inclusion() {
        let leaves = hex_leaves(&["a", "b", "c", "d"]);
        let root = hex::encode(tree_hash(&leaves));
        let proof = vec![
            serde_json::json!({"position": "right", "hash": hex::encode(leaves[1])}),
            serde_json::json!({"position": "right", "hash": hex::encode(tree_hash(&leaves[2..]))}),
        ];
        assert!(verify_inclusion(0, 4, &hex::encode(leaves[0]), &root, &proof).expect("verify"));
    }

    #[test]
    fn rejects_invalid_inclusion() {
        let leaves = hex_leaves(&["a", "b", "c"]);
        let root = hex::encode(tree_hash(&leaves));
        let proof = vec![serde_json::json!({"position": "right", "hash": hex::encode(leaves[1])})];
        assert!(!verify_inclusion(0, 3, &hex::encode(leaves[2]), &root, &proof).expect("verify"));
    }
}
