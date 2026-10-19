//! Bounded HTTP/1.1 record read on a newly authenticated Registry TLS connection.

use crate::error::{Error, Result};
use rustls::{ClientConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};

use super::web_media010::HeaderField010;
use super::web_origin_policy010::check_web_registry_response_policy_010;
use super::web_record_proofs010::check_web_registry_proofs_010;
use super::web_tls_origin010::connect_web_registry_tls_010;

const MAX_HTTP_HEADER: usize = 16_384;
const MAX_BODY: usize = 69_632;

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

fn unreachable() -> Error {
    Error::ValidationError("record.unreachable".into())
}

fn size_exceeded() -> Error {
    Error::ValidationError("size.exceeded".into())
}

/// Read a Content-Length HTTP/1.1 response on the authenticated connection,
/// then check its record proofs. Other framing and controller or mutation
/// history remain outside this bounded adapter; success is not full REG-08.
pub fn fetch_web_registry_record_010(
    did: &str,
    allowed_origins: &[&str],
    destination: SocketAddr,
    allowed_destinations: &[SocketAddr],
    root_der: &[u8],
    now: i64,
) -> Result<Vec<u8>> {
    let (connection, socket) = connect_web_registry_tls_010(
        did,
        allowed_origins,
        destination,
        allowed_destinations,
        root_der,
    )?;
    let rest = did.strip_prefix("did:sage:web:").ok_or_else(invalid)?;
    let (domain, agent) = rest.split_once(':').ok_or_else(invalid)?;
    let mut stream = StreamOwned::new(connection, socket);
    let request = format!("GET /.well-known/sage/agents/{agent} HTTP/1.1\r\nHost: {domain}\r\nAccept: application/json\r\nCache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| unreachable())?;
    read_web_registry_http_010(&mut stream, did, now)
}

fn read_web_registry_http_010(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    did: &str,
    now: i64,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let (status, fields, length) = parse_header_010(&mut reader)?;
    check_web_registry_response_policy_010(status, &fields, &[])?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|_| unreachable())?;
    check_web_registry_proofs_010(&body, did, now)?;
    Ok(body)
}

fn parse_header_010<R: BufRead>(reader: &mut R) -> Result<(u16, Vec<HeaderField010>, usize)> {
    let mut remaining = MAX_HTTP_HEADER;
    let mut line = |reader: &mut R| -> Result<String> {
        let mut raw = Vec::new();
        // BufRead::read_until may allocate without a bound, so consume only
        // the still permitted bytes through a bounded reader.
        let amount = reader
            .take((remaining + 1) as u64)
            .read_until(b'\n', &mut raw)
            .map_err(|_| unreachable())?;
        if amount == 0 || amount > remaining || !raw.ends_with(b"\r\n") {
            return Err(invalid());
        }
        remaining -= amount;
        String::from_utf8(raw[..raw.len() - 2].to_vec()).map_err(|_| invalid())
    };
    let status_line = line(reader)?;
    let status_bytes = status_line.as_bytes();
    if !status_line.starts_with("HTTP/1.1 ")
        || status_bytes.len() < 12
        || !status_bytes[9..12].iter().all(u8::is_ascii_digit)
        || (status_bytes.len() > 12 && status_bytes[12] != b' ')
    {
        return Err(invalid());
    }
    let status = status_line[9..12].parse().map_err(|_| invalid())?;
    let mut fields = Vec::new();
    loop {
        let value = line(reader)?;
        if value.is_empty() {
            break;
        }
        if fields.len() == 64 || value.starts_with([' ', '\t']) {
            return Err(invalid());
        }
        let (name, value) = value.split_once(':').ok_or_else(invalid)?;
        let field = HeaderField010 {
            name: name.to_owned(),
            value: value.trim_matches([' ', '\t']).to_owned(),
        };
        if field.name.is_empty()
            || !field
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
            || !field
                .value
                .bytes()
                .all(|c| (c >= 0x20 || c == b'\t') && c != 0x7f)
        {
            return Err(invalid());
        }
        fields.push(field);
    }
    let mut length = None;
    for field in &fields {
        if field.name.eq_ignore_ascii_case("transfer-encoding")
            || field.name.eq_ignore_ascii_case("trailer")
        {
            return Err(invalid());
        }
        if field.name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || field.value.is_empty()
                || !field.value.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(invalid());
            }
            let value: usize = field.value.parse().map_err(|_| size_exceeded())?;
            if value > MAX_BODY {
                return Err(size_exceeded());
            }
            length = Some(value);
        }
    }
    Ok((status, fields, length.ok_or_else(invalid)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn accepts_one_bounded_length() {
        let mut source = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
        let (status, _, length) = parse_header_010(&mut source).unwrap();
        assert_eq!((status, length), (200, 42));
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_framing() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 69633\r\n\r\n",
            "HTTP/1.1 200 OK\nContent-Length: 1\n\n",
        ] {
            assert!(parse_header_010(&mut Cursor::new(response)).is_err());
        }
    }
}
