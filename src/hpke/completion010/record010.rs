use super::*;

fn request_aad(w: &Raw) -> Vec<u8> {
    let a: BTreeMap<_, _> = w
        .iter()
        .filter(|(k, _)| k.as_str() != "payload" && k.as_str() != "signature")
        .collect();
    canonical(&a)
}
fn session_request(bytes: &[u8], now: i64) -> Result<(Raw, Vec<u8>)> {
    if bytes.len() > 32768 {
        return Err(bad());
    }
    crate::jcs::canonicalize(bytes).map_err(|_| bad())?;
    let mut names = WIRE.to_vec();
    names.extend(["session_id", "payload"]);
    let w = raw(bytes, &names)?;
    if string(&w, "encoding") != "session"
        || string(&w, "version") != "0.10.0"
        || !d::uuid(&string(&w, "id"))
    {
        return Err(bad());
    }
    let created = number(&w, "created")?;
    let expires = number(&w, "expires")?;
    if created < 0
        || expires > 9007199254740991
        || expires <= created
        || expires - created > 300
        || created > now + 30
        || now >= expires
    {
        return Err(bad());
    }
    for (k, n) in [("nonce", 16), ("signature", 64), ("session_id", 16)] {
        d::binary(&string(&w, k), n)?;
    }
    let encoded = string(&w, "payload");
    let body = B64.decode(&encoded).map_err(|_| bad())?;
    if body.len() < 36
        || body.len() > 16384
        || B64.encode(&body) != encoded
        || request_aad(&w).len() > 4033
    {
        return Err(bad());
    }
    Ok((w, body))
}
fn sample(clock: &mut dyn Clock, last: &mut Option<Stamp>) -> Result<Stamp> {
    let t = clock.now().map_err(|_| bad())?;
    if t.mono_ms < 0
        || t.unix < 0
        || t.unix > 9007199254740691
        || last.is_some_and(|p| t.mono_ms < p.mono_ms || t.unix < p.unix)
    {
        return Err(bad());
    }
    *last = Some(t);
    Ok(t)
}
impl AuthenticatedCompletion010 {
    pub(super) fn record_live(&self, t: Stamp) -> Result<()> {
        if self.closed
            || self.records.is_none()
            || t.mono_ms < self.created.mono_ms
            || t.mono_ms < self.active.mono_ms
            || t.unix < self.created.unix
            || t.mono_ms - self.created.mono_ms >= 3600000
            || t.mono_ms - self.active.mono_ms >= 600000
            || (!self.initiator && !self.confirmed && !live(t, self.created, self.expires))
        {
            return Err(bad());
        }
        Ok(())
    }
    fn begin_record(&mut self, e: &mut CompletionEndpoint010) -> Result<Stamp> {
        let r = (|| {
            if self.endpoint != e.identity {
                return Err(bad());
            }
            let t = e.sample()?;
            self.record_live(t)?;
            Ok(t)
        })();
        if r.is_err() {
            self.close()
        };
        r
    }
    /// Emit a signed session request with pinned tuple and JCS envelope AAD.
    /// Supports at most 16348 plaintext bytes, no metadata/task fields or HTTP.
    /// Return is the emission boundary; retries must reuse the exact wire bytes.
    /// Provisional responders cannot send. This API does not authorize execution.
    pub fn seal_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        plaintext: &[u8],
        ttl: i64,
    ) -> Result<Vec<u8>> {
        let start = self.begin_record(e)?;
        if (!self.initiator && !self.confirmed)
            || !(1..=300).contains(&ttl)
            || plaintext.len() > 16348
        {
            return Err(bad());
        }
        if e.current(&self.a, &self.b).is_err() {
            self.close();
            return Err(bad());
        }
        let (peer, role) = if self.initiator {
            (&self.tuple["respDid"], "initiator")
        } else {
            (&self.tuple["initDid"], "responder")
        };
        let mut w = envelope(
            &e.did,
            peer,
            &e.kid,
            &self.tuple["ctx"],
            false,
            &[],
            (start.unix, start.unix + ttl),
        )?;
        w["recipient"] = json!(peer);
        w["role"] = json!(role);
        w["encoding"] = json!("session");
        w["session_id"] = json!(self.tuple["sid"]);
        w.as_object_mut().ok_or_else(bad)?.remove("payload");
        let aad = canonical(&w);
        if aad.len() > 4033 {
            return Err(bad());
        }
        let wire = match self.records.as_mut().ok_or_else(bad)?.seal(plaintext, &aad) {
            Ok(w) => w,
            Err(_) => {
                self.close();
                return Err(bad());
            }
        };
        w["payload"] = json!(B64.encode(wire));
        let result = signed(
            w,
            b"sage-wire-request|0.10.0\n",
            e.signing.as_ref().ok_or_else(bad)?,
        );
        let end = match e.sample() {
            Ok(t) => t,
            Err(_) => {
                self.close();
                return Err(bad());
            }
        };
        if self.record_live(end).is_err()
            || end.mono_ms - start.mono_ms > 5000
            || end.unix >= start.unix + ttl
            || !pinned_live(end.unix, &self.a, &self.b)
        {
            self.close();
            return Err(bad());
        }
        self.active = end;
        Ok(result)
    }
    /// Verify signed session request, tuple, current keys and AEAD before the
    /// transport replay transaction. Publish sequence and confirmation together
    /// under exclusive access, releasing plaintext only on complete success.
    /// Later application rejection must not undo acceptance. This is not dispatch.
    pub fn open_request(&mut self, e: &mut CompletionEndpoint010, bytes: &[u8]) -> Result<Vec<u8>> {
        let start = self.begin_record(e)?;
        let (w, wire) = session_request(bytes, start.unix)?;
        let (did, recipient, kid, role, key) = if self.initiator {
            (
                &self.tuple["respDid"],
                &self.tuple["initDid"],
                &self.tuple["respKid"],
                "responder",
                self.b.signing(),
            )
        } else {
            (
                &self.tuple["initDid"],
                &self.tuple["respDid"],
                &self.tuple["initKid"],
                "initiator",
                self.a.signing(),
            )
        };
        for (k, v) in [
            ("did", did.as_str()),
            ("recipient", recipient),
            ("kid", kid),
            ("role", role),
            ("context_id", &self.tuple["ctx"]),
            ("session_id", &self.tuple["sid"]),
        ] {
            if string(&w, k) != v {
                return Err(bad());
            }
        }
        if e.current(&self.a, &self.b).is_err() {
            self.close();
            return Err(bad());
        }
        verify_wire(&w, false, key)?;
        let mut entry = reservation(&w)?;
        entry.context.clear();
        let expires = entry.expires;
        // Move only the record owner temporarily so the final gate can borrow the
        // rest of the authenticated state; the exclusive outer borrow remains held.
        let mut records = self.records.take().ok_or_else(bad)?;
        let mut accepted = None;
        let mut failed_gate = false;
        let result = records.open_checked(&wire, &request_aad(&w), || {
            let mut called = false;
            let result = e.replay.reserve_record(entry, &mut || {
                if called {
                    return Err(bad());
                }
                called = true;
                let result = (|| {
                    let t = sample(e.clock.as_mut(), &mut e.last)?;
                    // records is privately borrowed outside self during this gate.
                    if self.closed
                        || t.mono_ms < self.created.mono_ms
                        || t.mono_ms < self.active.mono_ms
                        || t.mono_ms - self.created.mono_ms >= 3600000
                        || t.mono_ms - self.active.mono_ms >= 600000
                        || (!self.initiator
                            && !self.confirmed
                            && !live(t, self.created, self.expires))
                        || t.mono_ms - start.mono_ms > 5000
                        || t.unix >= expires
                        || !pinned_live(t.unix, &self.a, &self.b)
                    {
                        return Err(bad());
                    }
                    accepted = Some(t);
                    Ok(())
                })();
                if result.is_err() {
                    failed_gate = true
                };
                result
            });
            if result.is_err() || !called || failed_gate {
                return Err(bad());
            }
            Ok(())
        });
        self.records = Some(records);
        if failed_gate {
            self.close()
        }
        let plaintext = result.map_err(|_| bad())?;
        self.confirmed = true;
        self.active = accepted.ok_or_else(bad)?;
        Ok(plaintext)
    }
}
