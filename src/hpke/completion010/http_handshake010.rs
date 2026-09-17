use super::record010::http010 as h;
use super::*;
impl CompletionEndpoint010 {
    /// Select HTTP permanently before any handshake attempt. Bare methods reject.
    pub fn bind_http(&mut self, target: &str) -> Result<()> {
        let authority = h::endpoint(target)?;
        if self.used || !self.http_target.is_empty() || self.signing.is_none() {
            return Err(bad());
        }
        self.http_target = target.into();
        self.http_authority = authority;
        Ok(())
    }
    fn http_end(&mut self, start: Stamp, expires: i64, a: &Pinned, b: &Pinned) -> Result<()> {
        let end = self.sample()?;
        if end.mono_ms - start.mono_ms > 5000 || end.unix >= expires || !pinned_live(end.unix, a, b)
        {
            return Err(bad());
        }
        Ok(())
    }
    /// Start an HTTP-bound handshake and privately retain exact request components.
    pub fn start_http(
        &mut self,
        recipient: &str,
        kid: &str,
        ttl: i64,
    ) -> Result<(PendingCompletion010, HTTPMessage010)> {
        let start = self.sample()?;
        if self.http_target.is_empty() {
            return Err(bad());
        }
        let (mut p, body) = self.start_inner(recipient, kid, ttl)?;
        let m = h::sign(self, &self.http_target, &self.http_authority, body, 0, None)?;
        self.http_end(start, p.expires, &p.a, &p.b)?;
        p.http = Some(h::context(&m, &h::headers(&m)?));
        Ok((p, m))
    }
    /// Verify both signatures before one replay reservation and emit bound completion.
    pub fn respond_http(
        &mut self,
        m: &HTTPMessage010,
        ttl: i64,
    ) -> Result<(AuthenticatedCompletion010, HTTPMessage010)> {
        let start = self.sample()?;
        let proof = h::prepare(&self.http_target, &self.http_authority, m, false, start)?;
        let (mut s, body) = self.respond_inner(&m.body, ttl, Some(&proof))?;
        let result = (|| {
            let response = h::sign(
                self,
                &self.http_target,
                &self.http_authority,
                body,
                200,
                Some(&h::context(m, &proof.headers)),
            )?;
            self.http_end(start, s.expires, &s.a, &s.b)?;
            Ok(response)
        })();
        match result {
            Ok(m) => {
                s.http_target = self.http_target.clone();
                s.http_authority = self.http_authority.clone();
                Ok((s, m))
            }
            Err(e) => {
                s.close();
                Err(e)
            }
        }
    }
}
impl PendingCompletion010 {
    /// Any attempted HTTP completion failure consumes one-shot pending material.
    pub fn complete_http(
        &mut self,
        e: &mut CompletionEndpoint010,
        m: &HTTPMessage010,
    ) -> Result<AuthenticatedCompletion010> {
        let result = (|| {
            let start = e.sample()?;
            if self.http.is_none() {
                return Err(bad());
            }
            let proof = h::prepare(&e.http_target, &e.http_authority, m, true, start)?;
            let mut s = self.complete_inner(e, &m.body, Some(&proof))?;
            s.http_target = e.http_target.clone();
            s.http_authority = e.http_authority.clone();
            Ok(s)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
/// Parse exactly one bounded HTTP/1.1 message obtained from authenticated TLS.
/// TLS is not established by this function. No chunking, pipelining or upgrades.
pub fn parse_http_010(raw: &[u8], target: &str, response: bool) -> Result<HTTPMessage010> {
    let authority = h::endpoint(target)?;
    if raw.len() > 73728 {
        return Err(bad());
    }
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(bad)?;
    if at > 36864 {
        return Err(bad());
    }
    let header = std::str::from_utf8(&raw[..at]).map_err(|_| bad())?;
    let lines: Vec<_> = header.split("\r\n").collect();
    if lines.len() < 2 || lines[0].len() > 4096 {
        return Err(bad());
    }
    if lines[1..].iter().map(|line| line.len() + 2).sum::<usize>() > 32768 {
        return Err(bad());
    }
    let mut m = HTTPMessage010 {
        method: String::new(),
        target: String::new(),
        authority: String::new(),
        status: 0,
        headers: vec![],
        body: raw[at + 4..].to_vec(),
    };
    if response {
        let parts: Vec<_> = lines[0].splitn(3, ' ').collect();
        if parts.len() != 3
            || parts[0] != "HTTP/1.1"
            || parts[1].len() != 3
            || !h::ascii(parts[2])
            || !parts[1].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad());
        }
        m.status = parts[1].parse().map_err(|_| bad())?;
        if !(200..=599).contains(&m.status) || m.status == 204 {
            return Err(bad());
        }
    } else {
        let path = target
            .strip_prefix(&format!("https://{authority}"))
            .ok_or_else(bad)?;
        if lines[0] != format!("POST {path} HTTP/1.1") {
            return Err(bad());
        }
        m.method = "POST".into();
        m.target = target.into();
        m.authority = authority.clone();
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut length = "";
    let mut host = "";
    for line in &lines[1..] {
        let (k, v) = line.split_once(':').ok_or_else(bad)?;
        if !h::token(k) {
            return Err(bad());
        }
        let k = k.to_ascii_lowercase();
        let v = v.trim_matches([' ', '\t']);
        if k == "content-length" {
            if seen.contains(&k) {
                return Err(bad());
            }
            length = v;
        }
        if k == "host" {
            if seen.contains(&k) {
                return Err(bad());
            }
            host = v;
        }
        if matches!(
            k.as_str(),
            "transfer-encoding" | "upgrade" | "expect" | "trailer" | "content-encoding"
        ) || (k == "connection" && (seen.contains(&k) || v != "close"))
        {
            return Err(bad());
        }
        seen.insert(k.clone());
        m.headers.push([k, v.into()]);
    }
    if length != m.body.len().to_string()
        || (!response && host != authority)
        || (response && seen.contains("host"))
    {
        return Err(bad());
    }
    h::headers(&m)?;
    Ok(m)
}
/// Serialize exact signed bytes with Content-Length and Connection: close.
pub fn encode_http_010(m: &HTTPMessage010, target: &str) -> Result<Vec<u8>> {
    h::headers(m)?;
    let authority = h::endpoint(target)?;
    let mut out = if m.status == 0 {
        if m.method != "POST" || m.target != target || m.authority != authority {
            return Err(bad());
        }
        format!(
            "POST {} HTTP/1.1\r\nHost: {authority}\r\n",
            target
                .strip_prefix(&format!("https://{authority}"))
                .ok_or_else(bad)?
        )
    } else {
        if !m.method.is_empty() || !m.target.is_empty() || !m.authority.is_empty() {
            return Err(bad());
        }
        format!("HTTP/1.1 {} SAGE\r\n", m.status)
    };
    for [k, v] in &m.headers {
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "connection"
        ) {
            return Err(bad());
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        m.body.len()
    ));
    let mut out = out.into_bytes();
    out.extend(&m.body);
    parse_http_010(&out, target, m.status != 0)?;
    Ok(out)
}
