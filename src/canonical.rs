use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("normalized object keys collide")]
    KeyCollision,
    #[error("unsupported canonical number")]
    UnsupportedNumber,
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hex::encode(hasher.finalize())
}

pub fn sha256_bytes(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}

pub fn nfc(value: &str) -> String {
    value.nfc().collect()
}

pub fn normalize_value(value: &Value) -> Result<Value, CanonicalError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
        Value::String(text) => Ok(Value::String(nfc(text))),
        Value::Array(items) => items
            .iter()
            .map(normalize_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => {
            let mut normalized = Map::new();
            for (key, value) in object {
                let key = nfc(key);
                if normalized.insert(key, normalize_value(value)?).is_some() {
                    return Err(CanonicalError::KeyCollision);
                }
            }
            Ok(Value::Object(normalized))
        }
    }
}

fn sorted_object(object: &Map<String, Value>) -> BTreeMap<&str, &Value> {
    object
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect()
}

pub fn canonical_encode(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let normalized = normalize_value(value)?;
    let mut output = String::new();
    write_value(&normalized, &mut output)?;
    Ok(output.into_bytes())
}

fn write_value(value: &Value, output: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => write_number(number, output)?,
        Value::String(text) => write_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(item, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            for (index, (key, item)) in sorted_object(object).into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_string(key, output);
                output.push(':');
                write_value(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn write_number(number: &Number, output: &mut String) -> Result<(), CanonicalError> {
    if let Some(value) = number.as_i64() {
        let _ = write!(output, "{value}");
        return Ok(());
    }
    if let Some(value) = number.as_u64() {
        let _ = write!(output, "{value}");
        return Ok(());
    }
    let value = number.as_f64().ok_or(CanonicalError::UnsupportedNumber)?;
    output.push_str(&python_float(value));
    Ok(())
}

fn python_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_owned()
        } else {
            "0.0".to_owned()
        };
    }
    if value.is_nan() || value.is_infinite() {
        return "null".to_owned();
    }

    let negative = value.is_sign_negative();
    let absolute = value.abs();
    let debug = format!("{absolute:?}");
    let (mantissa, exponent) = match debug.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap_or(0)),
        None => (debug.as_str(), 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };
    let mut digits = String::with_capacity(integer.len() + fraction.len());
    digits.push_str(integer);
    digits.push_str(fraction);
    let mut point = integer.len() as i32 + exponent;

    let leading = digits
        .chars()
        .take_while(|character| *character == '0')
        .count();
    if leading > 0 {
        digits.drain(..leading);
        point -= leading as i32;
    }
    while digits.ends_with('0') {
        digits.pop();
    }

    let mut result = String::new();
    if negative {
        result.push('-');
    }
    if digits.is_empty() {
        result.push_str("0.0");
        return result;
    }

    let exponent = point - 1;
    if !(-4..16).contains(&exponent) {
        result.push(digits.as_bytes()[0] as char);
        if digits.len() > 1 {
            result.push('.');
            result.push_str(&digits[1..]);
        }
        let sign = if exponent < 0 { '-' } else { '+' };
        let _ = write!(result, "e{sign}{:02}", exponent.unsigned_abs());
    } else if exponent >= 0 {
        let integer_digits = exponent as usize + 1;
        if digits.len() > integer_digits {
            result.push_str(&digits[..integer_digits]);
            result.push('.');
            result.push_str(&digits[integer_digits..]);
        } else {
            result.push_str(&digits);
            for _ in digits.len()..integer_digits {
                result.push('0');
            }
            result.push_str(".0");
        }
    } else {
        result.push_str("0.");
        for _ in 0..(-exponent - 1) {
            result.push('0');
        }
        result.push_str(&digits);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_nfc_and_sorted_keys() {
        let value = json!({"z": "e\u{301}", "a": {"b": 1, "a": [true, null]}});
        let encoded = canonical_encode(&value).expect("canonical encoding");
        assert_eq!(
            String::from_utf8(encoded).expect("utf8"),
            "{\"a\":{\"a\":[true,null],\"b\":1},\"z\":\"\\u{e9}\"}".replace("\\u{e9}", "é")
        );
    }

    #[test]
    fn formats_python_floats() {
        let cases = [
            (1.0, "1.0"),
            (1.5, "1.5"),
            (1e20, "1e+20"),
            (1e-7, "1e-07"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1.2345678901234567e30, "1.2345678901234567e+30"),
            (-0.0, "-0.0"),
        ];
        for (value, expected) in cases {
            assert_eq!(python_float(value), expected, "float {value}");
        }
    }

    #[test]
    fn escapes_control_characters() {
        let encoded = canonical_encode(&json!({"value": "\u{0001}\n\t"})).expect("encoding");
        assert_eq!(
            String::from_utf8(encoded).expect("utf8"),
            "{\"value\":\"\\u0001\\n\\t\"}"
        );
    }
}
