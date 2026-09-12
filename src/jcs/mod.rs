//! JSON Canonicalization Scheme (RFC 8785) as required by sage-spec
//! `02-jcs.md`: object members sorted by UTF-16 code units, ECMAScript
//! string escaping, ECMAScript `Number::toString` number formatting, no
//! whitespace. The input is parsed by a small JSON reader that keeps
//! number literals verbatim so that canonicalisation never depends on how
//! another library parsed them.

use crate::error::{Error, Result};

/// A parsed JSON value with the number literal preserved.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Number as written in the input
    Number(String),
    /// Decoded string
    String(String),
    /// Array
    Array(Vec<Value>),
    /// Object in input order (duplicate keys are rejected while parsing)
    Object(Vec<(String, Value)>),
}

/// Canonicalise a JSON document.
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(input)
        .map_err(|e| Error::ValidationError(format!("jcs: invalid UTF-8: {e}")))?;
    let value = parse(text)?;
    let mut out = String::with_capacity(text.len());
    write_value(&value, &mut out)?;
    Ok(out.into_bytes())
}

/// Parse a JSON document into a [`Value`].
pub fn parse(text: &str) -> Result<Value> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(Error::ValidationError("jcs: trailing characters".into()));
    }
    Ok(v)
}

/// Serialise a [`Value`] in canonical form.
pub fn to_string(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn err(&self, msg: &str) -> Error {
        Error::ValidationError(format!("jcs: {msg} at byte {}", self.i))
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, lit: &str) -> Result<()> {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(self.err(&format!("expected {lit}")))
        }
    }

    fn value(&mut self) -> Result<Value> {
        match self.peek() {
            Some(b'n') => self.expect("null").map(|_| Value::Null),
            Some(b't') => self.expect("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(self.err("unexpected character")),
        }
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => self.digits(),
            _ => return Err(self.err("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(self.err("invalid fraction"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(self.err("invalid exponent"));
            }
            self.digits();
        }
        Ok(Value::Number(
            std::str::from_utf8(&self.s[start..self.i])
                .unwrap()
                .to_string(),
        ))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
    }

    fn string(&mut self) -> Result<String> {
        self.expect("\"")?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err("bad escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                self.expect("\\u")
                                    .map_err(|_| self.err("lone high surrogate"))?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("lone low surrogate"));
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(ch).ok_or_else(|| self.err("invalid code point"))?,
                            );
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                c if c < 0x20 => return Err(self.err("control character in string")),
                _ => {
                    // copy one UTF-8 sequence
                    let len = utf8_len(c).ok_or_else(|| self.err("invalid UTF-8"))?;
                    let piece = std::str::from_utf8(&self.s[self.i..self.i + len])
                        .map_err(|_| self.err("invalid UTF-8"))?;
                    out.push_str(piece);
                    self.i += len;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        if self.i + 4 > self.s.len() {
            return Err(self.err("short \\u escape"));
        }
        let h =
            std::str::from_utf8(&self.s[self.i..self.i + 4]).map_err(|_| self.err("bad hex"))?;
        let v = u32::from_str_radix(h, 16).map_err(|_| self.err("bad hex"))?;
        self.i += 4;
        Ok(v)
    }

    fn array(&mut self) -> Result<Value> {
        self.expect("[")?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err("expected , or ]")),
            }
        }
    }

    fn object(&mut self) -> Result<Value> {
        self.expect("{")?;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key"));
            }
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(self.err("duplicate object key"));
            }
            self.ws();
            self.expect(":")?;
            self.ws();
            let v = self.value()?;
            members.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.err("expected , or }")),
            }
        }
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

fn write_value(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_to_string(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| {
                a.0.encode_utf16()
                    .collect::<Vec<u16>>()
                    .cmp(&b.0.encode_utf16().collect::<Vec<u16>>())
            });
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// ECMAScript `JSON.stringify` string escaping.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number::toString` applied to a JSON number literal.
pub fn number_to_string(literal: &str) -> Result<String> {
    let x: f64 = literal
        .parse()
        .map_err(|_| Error::ValidationError(format!("jcs: bad number {literal}")))?;
    if !x.is_finite() {
        return Err(Error::ValidationError(format!(
            "jcs: number out of range {literal}"
        )));
    }
    if x == 0.0 {
        return Ok("0".into()); // covers -0
    }
    let neg = x < 0.0;
    let sci = format!("{:e}", x.abs()); // shortest round-trip digits, e.g. "3.333333333333333e8"
    let (mant, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32; // number of significant digits
    let n = exp + 1; // position of the decimal point relative to the digits
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if k <= n && n <= 21 {
        s.push_str(&digits);
        s.push_str(&"0".repeat((n - k) as usize));
    } else if 0 < n && n <= 21 {
        s.push_str(&digits[..n as usize]);
        s.push('.');
        s.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        s.push_str("0.");
        s.push_str(&"0".repeat((-n) as usize));
        s.push_str(&digits);
    } else {
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        let e = n - 1;
        s.push(if e < 0 { '-' } else { '+' });
        s.push_str(&e.abs().to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8785_appendix_a() {
        let input = r#"{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", "literals": [null, true, false]}"#;
        let out = canonicalize(input.as_bytes()).unwrap();
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn utf16_key_order() {
        let input = r#"{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\u000f": "x", "1": "One", "\ud83d\ude02": "Smiley", "\u0080": "Control", "\u00f6": "Latin", "\n": "Newline", "\ufb31": "Hebrew"}"#;
        let out = String::from_utf8(canonicalize(input.as_bytes()).unwrap()).unwrap();
        let keys: Vec<&str> = out
            .trim_matches(|c| c == '{' || c == '}')
            .split(',')
            .map(|kv| kv.split(':').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "\"\\n\"",
                "\"\\u000f\"",
                "\"\\r\"",
                "\"1\"",
                "\"\u{80}\"",
                "\"\u{f6}\"",
                "\"\u{20ac}\"",
                "\"\u{1f602}\"",
                "\"\u{fb31}\""
            ]
        );
    }

    #[test]
    fn numbers() {
        for (lit, want) in [
            ("10", "10"),
            ("-0", "0"),
            ("1e21", "1e+21"),
            ("1.0", "1"),
            ("0.1", "0.1"),
            ("100000000000000000000", "100000000000000000000"),
            ("123456789012345680000", "123456789012345680000"),
            ("-1.5e-7", "-1.5e-7"),
            ("1e-7", "1e-7"),
            ("0.000001", "0.000001"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("9007199254740993", "9007199254740992"),
        ] {
            assert_eq!(number_to_string(lit).unwrap(), want, "{lit}");
        }
        assert!(number_to_string("1e400").is_err());
    }

    #[test]
    fn rejects_duplicates_and_garbage() {
        assert!(canonicalize(br#"{"a":1,"a":2}"#).is_err());
        assert!(canonicalize(br#"{"a":1,}"#).is_err());
        assert!(canonicalize(b"[1] x").is_err());
        assert!(canonicalize(br#""\ud800""#).is_err());
    }
}
