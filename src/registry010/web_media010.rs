//! Bounded REG-08 media checks over individual HTTP field lines.

use crate::error::{Error, Result};

/// One header or trailer field line before coalescing or decompression.
pub struct HeaderField010 {
    /// Original field name from one header or trailer line.
    pub name: String,
    /// Field value before list coalescing or content decoding.
    pub value: String,
}

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

fn valid_field(field: &HeaderField010) -> bool {
    !field.name.is_empty()
        && field
            .name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        && field
            .value
            .bytes()
            .all(|c| (c >= 0x20 || c == b'\t') && c != 0x7f)
}

/// Check only the REG-08 response media and coding boundary. A successful
/// result does not authenticate the origin, parse the body, or authorize a
/// Registry record. The trusted HTTP adapter must preserve duplicate lines
/// and trailer fields before passing them to this function.
pub fn check_web_registry_media_010(
    header: &[HeaderField010],
    trailer: &[HeaderField010],
) -> Result<()> {
    let mut content_type: Option<&str> = None;
    for field in header {
        if !valid_field(field) || field.name.eq_ignore_ascii_case("content-encoding") {
            return Err(invalid());
        }
        if field.name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(invalid());
            }
            content_type = Some(field.value.trim_matches([' ', '\t']));
        }
    }
    for field in trailer {
        if !valid_field(field)
            || field.name.eq_ignore_ascii_case("content-type")
            || field.name.eq_ignore_ascii_case("content-encoding")
        {
            return Err(invalid());
        }
    }
    if content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(name: &str, value: &str) -> HeaderField010 {
        HeaderField010 {
            name: name.into(),
            value: value.into(),
        }
    }

    #[test]
    fn exact_media_and_case_are_allowed() {
        assert!(
            check_web_registry_media_010(&[line("Content-Type", "application/json")], &[]).is_ok()
        );
        assert!(
            check_web_registry_media_010(&[line("cOnTeNt-TyPe", "\tApplication/JSON ")], &[])
                .is_ok()
        );
    }

    #[test]
    fn invalid_media_never_authorizes_a_record() {
        let bad_headers = [
            vec![],
            vec![line("Content-Type", "text/plain")],
            vec![line("Content-Type", "application/did+json")],
            vec![line("Content-Type", "application/problem+json")],
            vec![line("Content-Type", "application/json; charset=utf-8")],
            vec![line("Content-Type", "application/json, text/plain")],
            vec![
                line("Content-Type", "application/json"),
                line("content-type", "application/json"),
            ],
            vec![
                line("Content-Type", "application/json"),
                line("Content-Encoding", "gzip"),
            ],
            vec![
                line("Content-Type", "application/json"),
                line("Content-Encoding", "identity"),
            ],
            vec![line("Content-Type", "application/jſon")],
            vec![line(
                "Content-Type",
                "application/json\r\nContent-Encoding: gzip",
            )],
        ];
        for header in bad_headers {
            assert!(matches!(
                check_web_registry_media_010(&header, &[]),
                Err(Error::ValidationError(ref code)) if code == "record.invalid"
            ));
        }
        let header = [line("Content-Type", "application/json")];
        for trailer in [
            line("Content-Type", "text/plain"),
            line("Content-Encoding", "gzip"),
        ] {
            assert!(check_web_registry_media_010(&header, &[trailer]).is_err());
        }
    }
}
