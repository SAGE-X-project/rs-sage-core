//! Bounded canonical RFC 9421 carriage for authenticated session records.
use super::*;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serializer};

/// Exact content bytes and uncombined fields supplied by a trusted HTTP transport.
/// Metadata must derive from actual transport routing/status, never peer JSON or
/// Forwarded fields. TLS, framing and trusted route selection remain external.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HTTPMessage010 {
    /// Actual request method, or empty for a response.
    pub method: String,
    /// Actual absolute request target, or empty for a response.
    pub target: String,
    /// Actual request authority, or empty for a response.
    pub authority: String,
    /// Response status, or zero for a request.
    pub status: u16,
    /// Original field occurrences before any duplicate combination.
    pub headers: Vec<[String; 2]>,
    #[serde(with = "content")]
    /// Exact content bytes after trusted transfer framing.
    pub body: Vec<u8>,
}
mod content {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if STANDARD.encode(&v) != s {
            return Err(serde::de::Error::custom("invalid content"));
        }
        Ok(v)
    }
}
#[derive(Clone)]
pub(super) struct HTTPContext010 {
    method: String,
    target: String,
    authority: String,
    digest: String,
    signature: String,
    version: String,
}
pub(super) struct HTTPProof010 {
    message: HTTPMessage010,
    headers: Fields,
    params: Fields,
    input: String,
    signature: Vec<u8>,
    pub(super) start: Stamp,
}
const REQUEST: &str = "\"@method\" \"@target-uri\" \"@authority\" \"content-type\" \"content-digest\" \"x-sage-did\" \"x-sage-version\"";
const RESPONSE: &str = "\"@status\" \"@method\";req \"@target-uri\";req \"@authority\";req \"content-digest\";req \"signature\";req \"x-sage-version\";req \"content-type\" \"content-digest\" \"x-sage-did\" \"x-sage-version\"";
fn ascii(v: &str) -> bool {
    v.bytes().all(|b| (32..=126).contains(&b))
}
fn token(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn digest(b: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(b)))
}
fn headers(m: &HTTPMessage010) -> Result<Fields> {
    if m.body.len() > 32768 || m.headers.len() > 256 {
        return Err(bad());
    }
    let mut h = Fields::new();
    let mut total = 0;
    for [name, v] in &m.headers {
        let k = name.to_ascii_lowercase();
        total += name.len() + v.len() + 4;
        if !token(&k) || !ascii(v) || v.trim() != v || total > 32768 {
            return Err(bad());
        }
        let critical = matches!(
            k.as_str(),
            "signature"
                | "signature-input"
                | "content-digest"
                | "content-type"
                | "host"
                | "content-length"
        ) || k.starts_with("x-sage-");
        if (h.contains_key(&k) && critical)
            || matches!(
                k.as_str(),
                "content-encoding" | "transfer-encoding" | "trailer"
            )
            || k.starts_with("x-sage-meta-")
            || (matches!(k.as_str(), "signature" | "signature-input") && v.len() > 8192)
        {
            return Err(bad());
        }
        h.insert(k, v.clone());
    }
    if h.get("content-type").map(String::as_str) != Some("application/json")
        || h.get("x-sage-version").map(String::as_str) != Some("0.10.0")
        || h.get("x-sage-did").is_none_or(String::is_empty)
        || h.get("content-digest") != Some(&digest(&m.body))
        || h.get("content-length")
            .is_some_and(|v| *v != m.body.len().to_string())
        || h.get("host").is_some_and(|v| *v != m.authority)
    {
        return Err(bad());
    }
    Ok(h)
}
fn input(v: &str, response: bool) -> Result<Fields> {
    let prefix = format!("sig1=({})", if response { RESPONSE } else { REQUEST });
    let mut rest = v.strip_prefix(&prefix).ok_or_else(bad)?;
    let mut out = Fields::new();
    while !rest.is_empty() {
        rest = rest.strip_prefix(';').ok_or_else(bad)?;
        let (key, r) = rest.split_once('=').ok_or_else(bad)?;
        rest = r;
        if out.contains_key(key) {
            return Err(bad());
        }
        let value;
        match key {
            "keyid" | "alg" | "nonce" | "tag" => {
                let r = rest.strip_prefix('"').ok_or_else(bad)?;
                let (v, r) = r.split_once('"').ok_or_else(bad)?;
                if !ascii(v) || v.contains('\\') {
                    return Err(bad());
                }
                value = v;
                rest = r;
            }
            "created" | "expires" => {
                let (v, r) = rest
                    .split_once(';')
                    .map_or((rest, ""), |(v, _)| (v, &rest[v.len()..]));
                let n = v.parse::<i64>().map_err(|_| bad())?;
                if n < 0 || v.len() > 15 || n.to_string() != v {
                    return Err(bad());
                }
                value = v;
                rest = r;
            }
            _ => return Err(bad()),
        }
        out.insert(key.into(), value.into());
    }
    if out.len() != 6
        || out.get("alg").map(String::as_str) != Some("ed25519")
        || out.get("tag").map(String::as_str) != Some("sage-0.10.0")
    {
        return Err(bad());
    }
    Ok(out)
}
fn base(m: &HTTPMessage010, h: &Fields, input: &str, q: Option<&HTTPContext010>) -> Vec<u8> {
    let mut lines = vec![];
    let mut add = |k: &str, v: &str| lines.push(format!("{k}: {v}"));
    if let Some(q) = q {
        add("\"@status\"", &m.status.to_string());
        for (k, v) in [
            ("@method", &q.method),
            ("@target-uri", &q.target),
            ("@authority", &q.authority),
            ("content-digest", &q.digest),
            ("signature", &q.signature),
            ("x-sage-version", &q.version),
        ] {
            add(&format!("\"{k}\";req"), v);
        }
    } else {
        add("\"@method\"", &m.method);
        add("\"@target-uri\"", &m.target);
        add("\"@authority\"", &m.authority);
    }
    for k in [
        "content-type",
        "content-digest",
        "x-sage-did",
        "x-sage-version",
    ] {
        add(&format!("\"{k}\""), &h[k]);
    }
    add("\"@signature-params\"", input);
    lines.join("\n").into_bytes()
}
fn context(m: &HTTPMessage010, h: &Fields) -> HTTPContext010 {
    HTTPContext010 {
        method: m.method.clone(),
        target: m.target.clone(),
        authority: m.authority.clone(),
        digest: h["content-digest"].clone(),
        signature: h["signature"].clone(),
        version: h["x-sage-version"].clone(),
    }
}
impl AuthenticatedCompletion010 {
    /// Permanently select canonical HTTPS POST carriage before any records.
    /// Bare record APIs reject afterwards. The endpoint is trusted configuration.
    pub fn bind_http(&mut self, target: &str) -> Result<()> {
        let u: http::Uri = target.parse().map_err(|_| bad())?;
        let authority = u.authority().ok_or_else(bad)?.as_str();
        if u.scheme_str() != Some("https")
            || authority.is_empty()
            || authority != authority.to_ascii_lowercase()
            || authority.ends_with(":443")
            || authority.contains('@')
            || target.contains('#')
            || !ascii(target)
            || target.contains(['"', '\\', ' '])
            || !target
                .strip_prefix(&format!("https://{authority}"))
                .is_some_and(|p| p.starts_with('/'))
            || u != target
            || self.closed
            || !self.http_target.is_empty()
            || !self.sent.is_empty()
            || !self.received.is_empty()
        {
            return Err(bad());
        }
        self.http_target = target.into();
        self.http_authority = authority.into();
        Ok(())
    }
    fn prepare_http(
        &self,
        m: &HTTPMessage010,
        response: bool,
        start: Stamp,
    ) -> Result<HTTPProof010> {
        if self.http_target.is_empty()
            || (!response
                && (m.method != "POST"
                    || m.target != self.http_target
                    || m.authority != self.http_authority
                    || m.status != 0))
            || (response
                && (!m.method.is_empty()
                    || !m.target.is_empty()
                    || !m.authority.is_empty()
                    || !(200..=599).contains(&m.status)
                    || m.status == 204))
        {
            return Err(bad());
        }
        let h = headers(m)?;
        let v = h.get("signature-input").ok_or_else(bad)?;
        let params = input(v, response)?;
        let value = h.get("signature").ok_or_else(bad)?;
        let encoded = value
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(bad)?;
        let signature = STANDARD.decode(encoded).map_err(|_| bad())?;
        if signature.len() != 64 || STANDARD.encode(&signature) != encoded {
            return Err(bad());
        }
        Ok(HTTPProof010 {
            message: m.clone(),
            params,
            input: v[5..].into(),
            headers: h,
            signature,
            start,
        })
    }
    pub(super) fn verify_http(&self, p: &HTTPProof010, w: &Raw) -> Result<()> {
        for (param, field) in [
            ("keyid", "kid"),
            ("created", "created"),
            ("expires", "expires"),
            ("nonce", "nonce"),
        ] {
            let value = if matches!(field, "created" | "expires") {
                w[field].get().into()
            } else {
                string(w, field)
            };
            if p.params.get(param) != Some(&value) {
                return Err(bad());
            }
        }
        if p.headers["x-sage-did"] != string(w, "did") {
            return Err(bad());
        }
        for (k, f) in [
            ("x-sage-message-id", "id"),
            ("x-sage-context-id", "context_id"),
            ("x-sage-task-id", "task_id"),
        ] {
            if p.headers
                .get(k)
                .is_some_and(|v| string(w, f).is_empty() || *v != string(w, f))
            {
                return Err(bad());
            }
        }
        let q = if p.message.status != 0 {
            Some(
                self.sent
                    .get(&string(w, "message_id"))
                    .and_then(|r| r.http.as_ref())
                    .ok_or_else(bad)?,
            )
        } else {
            None
        };
        let key = if self.initiator {
            self.b.signing()
        } else {
            self.a.signing()
        };
        verify(
            &base(&p.message, &p.headers, &p.input, q),
            &p.signature,
            key,
        )
    }
    fn sign_http(
        &self,
        e: &CompletionEndpoint010,
        body: Vec<u8>,
        status: u16,
        q: Option<&HTTPContext010>,
    ) -> Result<HTTPMessage010> {
        let w: Raw = serde_json::from_slice(&body).map_err(|_| bad())?;
        let mut m = HTTPMessage010 {
            method: String::new(),
            target: String::new(),
            authority: String::new(),
            status,
            headers: vec![],
            body,
        };
        let components = if q.is_none() {
            m.method = "POST".into();
            m.target = self.http_target.clone();
            m.authority = self.http_authority.clone();
            REQUEST
        } else {
            RESPONSE
        };
        let input=format!("({components});keyid=\"{}\";alg=\"ed25519\";created={};expires={};nonce=\"{}\";tag=\"sage-0.10.0\"",string(&w,"kid"),w["created"].get(),w["expires"].get(),string(&w,"nonce"));
        let mut h = Fields::from([
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest(&m.body)),
            ("x-sage-did".into(), string(&w, "did")),
            ("x-sage-version".into(), "0.10.0".into()),
            ("signature-input".into(), format!("sig1={input}")),
        ]);
        h.insert(
            "signature".into(),
            format!(
                "sig1=:{}:",
                STANDARD.encode(
                    e.signing
                        .as_ref()
                        .ok_or_else(bad)?
                        .sign(&base(&m, &h, &input, q))
                        .to_bytes()
                )
            ),
        );
        for k in [
            "content-type",
            "content-digest",
            "x-sage-did",
            "x-sage-version",
            "signature-input",
            "signature",
        ] {
            m.headers.push([k.into(), h[k].clone()]);
        }
        Ok(m)
    }
    fn http_end(&mut self, e: &mut CompletionEndpoint010, start: Stamp, ttl: i64) -> Result<()> {
        let r = (|| {
            let end = e.sample()?;
            self.record_live(end)?;
            if end.mono_ms - start.mono_ms > 5000
                || end.unix >= start.unix + ttl
                || !pinned_live(end.unix, &self.a, &self.b)
            {
                return Err(bad());
            }
            Ok(())
        })();
        if r.is_err() {
            self.close();
        }
        r
    }
    /// Sign a session request and its HTTP binding; retain the exact request signature.
    pub fn seal_http_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        data: &[u8],
        ttl: i64,
    ) -> Result<HTTPMessage010> {
        let start = self.begin_record(e)?;
        if self.http_target.is_empty() {
            return Err(bad());
        }
        let b = self.seal_request_inner(e, data, ttl)?;
        let m = self.sign_http(e, b, 0, None)?;
        self.http_end(e, start, ttl)?;
        let w: Raw = serde_json::from_slice(&m.body).map_err(|_| bad())?;
        self.sent.get_mut(&string(&w, "id")).ok_or_else(bad)?.http =
            Some(context(&m, &headers(&m)?));
        Ok(m)
    }
    /// Verify both signatures before one replay/sequence acceptance.
    pub fn open_http_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        m: &HTTPMessage010,
    ) -> Result<Vec<u8>> {
        let start = self.begin_record(e)?;
        let p = self.prepare_http(m, false, start)?;
        let data = self.open_request_inner(e, &m.body, Some(&p))?;
        let w: Raw = serde_json::from_slice(&m.body).map_err(|_| bad())?;
        self.received
            .get_mut(&string(&w, "id"))
            .ok_or_else(bad)?
            .http = Some(context(m, &p.headers));
        Ok(data)
    }
    /// Sign a terminal response bound to an internally retained HTTP request.
    pub fn seal_http_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        message_id: &str,
        data: &[u8],
        error: Option<&str>,
        ttl: i64,
        status: u16,
    ) -> Result<HTTPMessage010> {
        let start = self.begin_record(e)?;
        if self.http_target.is_empty() || !(200..=599).contains(&status) || status == 204 {
            return Err(bad());
        }
        let q = self
            .received
            .get(message_id)
            .and_then(|r| r.http.clone())
            .ok_or_else(bad)?;
        let b = self.seal_response_inner(e, message_id, data, error, ttl)?;
        let m = self.sign_http(e, b, status, Some(&q))?;
        self.http_end(e, start, ttl)?;
        Ok(m)
    }
    /// Accept one terminal response after HTTP, envelope, AEAD and replay checks.
    pub fn open_http_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        m: &HTTPMessage010,
    ) -> Result<SessionResponse010> {
        let start = self.begin_record(e)?;
        let p = self.prepare_http(m, true, start)?;
        self.open_response_inner(e, &m.body, Some(&p))
    }
}

#[cfg(test)]
pub(in crate::hpke::completion010) fn resign_test(
    m: &mut HTTPMessage010,
    e: &CompletionEndpoint010,
    q: Option<&HTTPMessage010>,
) {
    m.headers
        .iter_mut()
        .find(|p| p[0] == "content-digest")
        .unwrap()[1] = digest(&m.body);
    let h: Fields = m
        .headers
        .iter()
        .map(|p| (p[0].clone(), p[1].clone()))
        .collect();
    let context = q.map(|q| {
        let h: Fields = q
            .headers
            .iter()
            .map(|p| (p[0].clone(), p[1].clone()))
            .collect();
        context(q, &h)
    });
    let sig = e.signing.as_ref().unwrap().sign(&base(
        m,
        &h,
        &h["signature-input"][5..],
        context.as_ref(),
    ));
    m.headers.iter_mut().find(|p| p[0] == "signature").unwrap()[1] =
        format!("sig1=:{}:", STANDARD.encode(sig.to_bytes()));
}

#[cfg(test)]
#[test]
fn admission_bounds() {
    let mut m = HTTPMessage010 {
        method: "POST".into(),
        target: "https://agent.example/messages".into(),
        authority: "agent.example".into(),
        status: 0,
        body: vec![b'x'; 32768],
        headers: vec![],
    };
    m.headers = vec![
        ["content-type".into(), "application/json".into()],
        ["x-sage-version".into(), "0.10.0".into()],
        [
            "x-sage-did".into(),
            "did:sage:web:agent.example:alice".into(),
        ],
        ["content-digest".into(), digest(&m.body)],
        ["signature".into(), "a".repeat(8192)],
        ["signature-input".into(), "a".repeat(8192)],
    ];
    assert!(headers(&m).is_ok());
    let size: usize = m.headers.iter().map(|p| p[0].len() + p[1].len() + 4).sum();
    m.headers
        .push(["padding".into(), "p".repeat(32768 - size - 11)]);
    assert!(headers(&m).is_ok());
    m.headers.last_mut().unwrap()[1].push('p');
    assert!(headers(&m).is_err());
    m.headers.pop();
    m.headers[4][1].push('a');
    assert!(headers(&m).is_err());
    m.headers[4][1].pop();
    m.body.push(b'x');
    assert!(headers(&m).is_err());
    let good=format!("sig1=({REQUEST});keyid=\"did:sage:web:agent.example:alice#signing-1\";alg=\"ed25519\";created=100;expires=400;nonce=\"AAAAAAAAAAAAAAAAAAAAAA\";tag=\"sage-0.10.0\"");
    assert!(input(&good, false).is_ok());
    for v in [
        format!("{good};created=100"),
        format!("{good}, sig2=()"),
        good.replace(";created=100", ";created=0100"),
        good.replace(";created=100", ";created=-1"),
        good.replace(";created=100", ";created=1.0"),
        good.replace(";tag=\"sage-0.10.0\"", ""),
        good.replace(";nonce=\"", ";nonce=\"\\"),
        good.replace(";alg=", "; alg="),
    ] {
        assert!(input(&v, false).is_err());
    }
}
