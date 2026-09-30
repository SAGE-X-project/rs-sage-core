//! Bounded REG-08 JSON response wrapper checks without record authorization.

use crate::error::{Error, Result};
use crate::jcs::{self, Value};

const MAX_BODY: usize = 69_632;
const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

fn size_exceeded() -> Error {
    Error::ValidationError("size.exceeded".into())
}

fn bounded_depth(raw: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut string = false;
    let mut escape = false;
    for byte in raw {
        if string {
            if escape {
                escape = false;
            } else if *byte == b'\\' {
                escape = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else if *byte == b'"' {
            string = true;
        } else if matches!(*byte, b'{' | b'[') {
            depth += 1;
            if depth > 64 {
                return false;
            }
        } else if matches!(*byte, b'}' | b']') {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0 && !string && !escape
}

fn valid_numbers(value: &Value) -> bool {
    match value {
        Value::Number(literal) => literal.parse::<f64>().is_ok_and(|number| {
            number.is_finite() && !(number == 0.0 && number.is_sign_negative())
        }),
        Value::Object(members) => members.iter().all(|(_, value)| valid_numbers(value)),
        Value::Array(values) => values.iter().all(valid_numbers),
        _ => true,
    }
}

fn exact_integer(value: &Value) -> Option<i64> {
    let Value::Number(literal) = value else {
        return None;
    };
    let (negative, text) = if let Some(rest) = literal.strip_prefix('-') {
        (true, rest)
    } else {
        (false, literal.as_str())
    };
    let (mantissa, exponent) = if let Some((mantissa, exponent)) = text.split_once(['e', 'E']) {
        let exponent: i64 = exponent.parse().ok()?;
        if !(-100_000..=100_000).contains(&exponent) {
            return None;
        }
        (mantissa, exponent)
    } else {
        (text, 0)
    };
    let (digits, fraction) = if let Some((whole, fraction)) = mantissa.split_once('.') {
        (format!("{whole}{fraction}"), fraction.len() as i64)
    } else {
        (mantissa.to_string(), 0)
    };
    let mut digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return (!negative).then_some(0);
    }
    let mut scale = exponent - fraction;
    if scale < 0 {
        let trailing = (digits.len() - digits.trim_end_matches('0').len()) as i64;
        if trailing < -scale {
            return None;
        }
        digits = &digits[..digits.len() - (-scale as usize)];
        scale = 0;
    }
    if scale > 16 || digits.len() as i64 + scale > 16 {
        return None;
    }
    let number: i64 = format!("{digits}{}", "0".repeat(scale as usize))
        .parse()
        .ok()?;
    if number > MAX_EXACT_INTEGER {
        return None;
    }
    Some(if negative { -number } else { number })
}

/// Check the bounded web Registry JSON wrapper and its lifetime. The nested
/// record remains unvalidated; success does not authenticate an HTTPS origin,
/// verify key proofs, or authorize any protected operation. A trusted adapter
/// must stop reading at the first byte beyond the body limit.
pub fn check_web_registry_envelope_010(raw: &[u8], now: i64) -> Result<()> {
    if raw.len() > MAX_BODY {
        return Err(size_exceeded());
    }
    if raw.is_empty() || raw.starts_with(&[0xef, 0xbb, 0xbf]) || !bounded_depth(raw) {
        return Err(invalid());
    }
    let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
    let value = jcs::parse(text).map_err(|_| invalid())?;
    if !valid_numbers(&value) {
        return Err(invalid());
    }
    let Value::Object(members) = value else {
        return Err(invalid());
    };
    if members.len() != 3 {
        return Err(invalid());
    }
    let field = |name| {
        members
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    if !matches!(field("record"), Some(Value::Object(_))) {
        return Err(invalid());
    }
    let issued = field("issued")
        .and_then(exact_integer)
        .ok_or_else(invalid)?;
    let expires = field("expires")
        .and_then(exact_integer)
        .ok_or_else(invalid)?;
    if !(-MAX_EXACT_INTEGER..=MAX_EXACT_INTEGER).contains(&now)
        || issued > now
        || now >= expires
        || expires <= issued
        || expires - issued > 5
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_wrapper_and_lifetime() {
        let good = br#"{"record":{},"issued":100,"expires":105}"#;
        assert!(check_web_registry_envelope_010(good, 100).is_ok());
        assert!(check_web_registry_envelope_010(good, 104).is_ok());
        assert!(check_web_registry_envelope_010(good, 105).is_err());
        for bad in [
            &br#"{"record":{},"issued":100,"issued":100,"expires":105}"#[..],
            &br#"{"record":{"a":1,"a":2},"issued":100,"expires":105}"#[..],
            &br#"{"record":{},"issued":100,"expires":106}"#[..],
            &br#"{"record":{},"issued":-0,"expires":105}"#[..],
            &br#"{"record":{},"issued":100,"expires":105,"extra":0}"#[..],
            &br#"{"record":{},"issued":"100","expires":105}"#[..],
        ] {
            assert!(check_web_registry_envelope_010(bad, 100).is_err());
        }
        assert!(matches!(
            check_web_registry_envelope_010(&vec![b' '; MAX_BODY + 1], 100),
            Err(Error::ValidationError(ref code)) if code == "size.exceeded"
        ));
        let prefix = r#"{"record":{"pad":""#;
        let suffix = r#""},"issued":100,"expires":105}"#;
        let boundary = format!(
            "{}{}{}",
            prefix,
            "a".repeat(MAX_BODY - prefix.len() - suffix.len()),
            suffix
        );
        assert_eq!(boundary.len(), MAX_BODY);
        assert!(check_web_registry_envelope_010(boundary.as_bytes(), 100).is_ok());
        let deep = format!(
            "{{\"record\":{}0{},\"issued\":100,\"expires\":105}}",
            "[".repeat(64),
            "]".repeat(64)
        );
        assert!(check_web_registry_envelope_010(deep.as_bytes(), 100).is_err());
    }
}
