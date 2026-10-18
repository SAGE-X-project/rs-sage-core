//! Explicit ownership of the existing authenticated HTTP application metadata.
use super::*;
use serde::de::Error as _;

/// A non-cloneable HTTP application session. It exposes neither its inner
/// session nor a conversion to the metadata-free owner. No dispatch grant.
pub struct HTTPApplicationOwner010 {
    inner: NonHTTPOwner010,
}

/// Owned accepted request data. A zero/fabricated verification flag is not an input.
pub struct HTTPApplicationRequest010 {
    payload: Vec<u8>,
    metadata: Option<BTreeMap<String, String>>,
    sender: String,
    recipient: String,
    kid: String,
    id: String,
    context: String,
    session: String,
}
impl HTTPApplicationRequest010 {
    /// Accepted immutable application bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Authenticated optional data; absent differs from a present empty object.
    pub fn metadata(&self) -> Option<&BTreeMap<String, String>> {
        self.metadata.as_ref()
    }
    /// Exact envelope sender, never selected from metadata.
    pub fn sender(&self) -> &str {
        &self.sender
    }
    /// Exact envelope recipient.
    pub fn recipient(&self) -> &str {
        &self.recipient
    }
    /// Exact role-bound signing key URL.
    pub fn key_id(&self) -> &str {
        &self.kid
    }
    /// Authenticated envelope identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Fixed session context identifier.
    pub fn context_id(&self) -> &str {
        &self.context
    }
    /// Fixed session identifier.
    pub fn session_id(&self) -> &str {
        &self.session
    }
}

/// An owned, cryptographically correlated terminal response. Success is data,
/// not permission for local effects or application execution.
pub struct HTTPApplicationResponse010 {
    request: HTTPApplicationRequest010,
    in_reply_to: String,
    success: bool,
    error: String,
}
impl HTTPApplicationResponse010 {
    /// Authenticated response envelope fields and immutable bytes.
    pub fn envelope(&self) -> &HTTPApplicationRequest010 {
        &self.request
    }
    /// Accepted immutable response bytes.
    pub fn data(&self) -> &[u8] {
        self.request.payload()
    }
    /// Independently authenticated response metadata.
    pub fn metadata(&self) -> Option<&BTreeMap<String, String>> {
        self.request.metadata()
    }
    /// Exact request identifier matched against retained state.
    pub fn in_reply_to(&self) -> &str {
        &self.in_reply_to
    }
    /// Authenticated transport result, not authorization.
    pub fn success(&self) -> bool {
        self.success
    }
    /// Authenticated transport error, empty for success.
    pub fn error(&self) -> &str {
        &self.error
    }
}

impl AuthenticatedCompletion010 {
    /// Consume an unused session and bind exact trusted HTTPS carriage. All
    /// failures consume and erase it; Rust does not return the old handle.
    /// Existing HTTP-handshake targets must match, including provisional receive.
    ///
    /// ```compile_fail
    /// use sage_crypto_core::hpke::completion010::{AuthenticatedCompletion010, CompletionEndpoint010};
    /// fn cannot_reuse(session: AuthenticatedCompletion010, endpoint: &CompletionEndpoint010) {
    ///     let _owner = session.into_http_application(endpoint, "https://agent.example/messages");
    ///     let _ = session.state();
    /// }
    /// ```
    pub fn into_http_application(
        mut self,
        e: &CompletionEndpoint010,
        target: &str,
    ) -> Result<HTTPApplicationOwner010> {
        let authority = match record010::http010::endpoint(target) {
            Ok(authority) => authority,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        if self.closed
            || self.application
            || self.record_used
            || self.records.is_none()
            || !self.sent.is_empty()
            || !self.received.is_empty()
            || self.endpoint != e.identity
            || e.signing.is_none()
            || (!self.http_target.is_empty()
                && (self.http_target != target || self.http_authority != authority))
        {
            self.close();
            return Err(bad());
        }
        self.http_target = target.into();
        self.http_authority = authority;
        self.application = true;
        let sampled = e.last.unwrap_or(self.created);
        let life = OwnerLife(Arc::new(Mutex::new(OwnerLife::snapshot(&self, sampled))));
        Ok(HTTPApplicationOwner010 {
            inner: NonHTTPOwner010 {
                session: self,
                sampled,
                life,
            },
        })
    }
}
impl HTTPApplicationOwner010 {
    /// Erase this owner. Its private inner Drop also erases on ordinary drop.
    pub fn close(&mut self) {
        self.inner.close();
    }
    /// Fixed local/peer identifiers, not a current authorization permit.
    pub fn participants(&self) -> Result<(String, String)> {
        let s = &self.inner.session;
        if s.closed
            || !s.application
            || s.records.is_none()
            || self.inner.life.0.lock().map_or(true, |life| life.closed)
            || s.tuple.get("sid").is_none_or(String::is_empty)
        {
            return Err(bad());
        }
        if s.initiator {
            Ok((s.tuple["initDid"].clone(), s.tuple["respDid"].clone()))
        } else {
            Ok((s.tuple["respDid"].clone(), s.tuple["initDid"].clone()))
        }
    }
    /// Bounded local clock sample; no current Registry claim.
    pub fn local_now(&mut self, e: &mut CompletionEndpoint010) -> Result<i64> {
        self.inner.local_now(e)
    }
    /// Start of a fresh authority observation, not a portable dispatch grant.
    pub fn observe(&mut self, e: &mut CompletionEndpoint010) -> Result<i64> {
        self.inner.observe(e)
    }
    /// Revalidate current role-bound Registry keys and session lifetime.
    pub fn check(&mut self, e: &mut CompletionEndpoint010) -> Result<()> {
        self.inner.local_now(e)?;
        self.inner.guarded(e, |s, e| s.check(e))
    }
    /// Seal exact content and optional metadata in the existing full signature/AAD.
    pub fn seal_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        data: &[u8],
        metadata: Option<&BTreeMap<String, String>>,
        ttl: i64,
    ) -> Result<HTTPMessage010> {
        let metadata = copy_metadata(metadata)?;
        if data.len() > 16348 {
            return Err(bad());
        }
        let data = data.to_vec();
        self.inner.local_now(e)?;
        self.inner.guarded(e, |s, e| {
            s.seal_http_request_metadata(e, &data, metadata.as_ref(), ttl)
        })
    }
    /// Release owned data only after crypto/replay acceptance and final mirror sample.
    pub fn open_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        message: &HTTPMessage010,
    ) -> Result<HTTPApplicationRequest010> {
        if message.body.len() > 32768 || message.headers.len() > 256 {
            return Err(bad());
        }
        // A shared immutable borrow of Vec/String fields cannot be mutated by
        // a safe Rust provider. Common HTTP admission bounds headers before
        // constructing its owned proof; avoid an earlier unbounded clone.
        self.inner.local_now(e)?;
        self.inner.guarded(e, |s, e| {
            let data = s.open_http_application_request(e, message)?;
            accepted_view(data, &message.body)
        })
    }
    /// Seal one retained-request-correlated response, with independent metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        id: &str,
        data: &[u8],
        metadata: Option<&BTreeMap<String, String>>,
        error: Option<&str>,
        ttl: i64,
        status: u16,
    ) -> Result<HTTPMessage010> {
        let metadata = copy_metadata(metadata)?;
        if data.len() > 16348 {
            return Err(bad());
        }
        let data = data.to_vec();
        self.inner.local_now(e)?;
        self.inner.guarded(e, |s, e| {
            s.seal_http_response_metadata(e, id, &data, metadata.as_ref(), error, ttl, status)
        })
    }
    /// Accept exactly one terminal response; final sampling errors do not roll
    /// back already-published replay denial or restore a retry/terminal right.
    pub fn open_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        message: &HTTPMessage010,
    ) -> Result<HTTPApplicationResponse010> {
        if message.body.len() > 32768 || message.headers.len() > 256 {
            return Err(bad());
        }
        // A shared immutable borrow of Vec/String fields cannot be mutated by
        // a safe Rust provider. Common HTTP admission bounds headers before
        // constructing its owned proof; avoid an earlier unbounded clone.
        self.inner.local_now(e)?;
        self.inner.guarded(e, |s, e| {
            let response = s.open_http_application_response(e, message)?;
            Ok(HTTPApplicationResponse010 {
                request: accepted_view(response.data, &message.body)?,
                in_reply_to: response.message_id,
                success: response.success,
                error: response.error,
            })
        })
    }
}
fn accepted_view(payload: Vec<u8>, bytes: &[u8]) -> Result<HTTPApplicationRequest010> {
    let fields: Raw = serde_json::from_slice(bytes).map_err(|_| bad())?;
    let metadata = read_metadata(fields.get("metadata").map(Box::as_ref))?;
    Ok(HTTPApplicationRequest010 {
        payload,
        metadata,
        sender: string(&fields, "did"),
        recipient: string(&fields, "recipient"),
        kid: string(&fields, "kid"),
        id: string(&fields, "id"),
        context: string(&fields, "context_id"),
        session: string(&fields, "session_id"),
    })
}
pub(in crate::hpke::completion010) fn copy_metadata(
    metadata: Option<&BTreeMap<String, String>>,
) -> Result<Option<BTreeMap<String, String>>> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    if metadata.len() > 32 {
        return Err(bad());
    }
    for (key, value) in metadata {
        let mut bytes = key.bytes();
        if key.len() > 32
            || !bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || value.len() > 1024
        {
            return Err(bad());
        }
    }
    if canonical(metadata).len() > 4096 {
        return Err(bad());
    }
    Ok(Some(metadata.clone()))
}
pub(in crate::hpke::completion010) fn read_metadata(
    raw: Option<&RawValue>,
) -> Result<Option<BTreeMap<String, String>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.get().len() > 32768 {
        return Err(bad());
    }
    struct Metadata;
    impl<'de> Visitor<'de> for Metadata {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique string metadata object")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut access: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, String>()? {
                if values.len() >= 32 || values.insert(key, value).is_some() {
                    return Err(M::Error::custom("invalid metadata"));
                }
            }
            Ok(values)
        }
    }
    // Object deserialization explicitly rejects present null. String decoding
    // rejects invalid UTF-8 and unpaired surrogate escapes without replacement.
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let metadata =
        serde::de::Deserializer::deserialize_map(&mut decoder, Metadata).map_err(|_| bad())?;
    decoder.end().map_err(|_| bad())?;
    copy_metadata(Some(&metadata))
}
