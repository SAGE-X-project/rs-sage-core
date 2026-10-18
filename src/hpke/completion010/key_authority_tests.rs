use super::*;

type Trace = Rc<RefCell<Vec<Value>>>;

// Prevalidated static snapshots, not a proof verifier or an actual rotation.
struct AuthoritySource {
    control: Controls,
    endpoint: &'static str,
    rotated: bool,
    trace: Trace,
}
impl Source for AuthoritySource {
    fn read(&mut self, did: &str) -> Result<Snapshot> {
        let result = self.control.read(did);
        match result {
            Ok(mut snapshot) => {
                if self.rotated && did == BOB {
                    assert_eq!(snapshot.keys.len(), 2);
                    assert_eq!(snapshot.keys[0].name, "kem-1");
                    snapshot.keys[0].state = "revoked".into();
                    snapshot.keys.insert(
                        1,
                        Key {
                            name: "kem-2".into(),
                            alg: "x25519".into(),
                            material: hex::encode(x25519([7; 32], X25519_BASEPOINT_BYTES)),
                            state: "accepted".into(),
                            expires: None,
                        },
                    );
                    snapshot.version = "3".into();
                }
                // Another accepted key keeps selected-key revocation consistent
                // with an active record and exercises exact-name no-fallback.
                let seed = if did == BOB { 9 } else { 8 };
                snapshot.keys.push(Key {
                    name: "signing-2".into(),
                    alg: "ed25519".into(),
                    material: hex::encode(
                        SigningKey::from_bytes(&[seed; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                    state: "accepted".into(),
                    expires: None,
                });
                snapshot.digest = hex::encode(Sha256::digest(canonical(&snapshot.keys)));
                self.trace.borrow_mut().push(json!({
                    "endpoint": self.endpoint,
                    "requested_did": did,
                    "snapshot": snapshot,
                }));
                Ok(snapshot)
            }
            Err(error) => {
                self.trace.borrow_mut().push(json!({
                    "endpoint": self.endpoint,
                    "requested_did": did,
                    "error": "source",
                }));
                Err(error)
            }
        }
    }
}

// Track only successful publication, separately from Source reads.
struct AuthorityReplay {
    inner: Replay,
    endpoint: &'static str,
    trace: Trace,
}
impl ReplayStore010 for AuthorityReplay {
    fn reserve(&mut self, value: Replay010) -> Result<()> {
        let context = value.context.clone();
        self.inner.reserve(value)?;
        self.trace.borrow_mut().push(json!({
            "endpoint": self.endpoint,
            "kind": "handshake",
            "context": context,
            "retained_entries": self.inner.seen.len(),
        }));
        Ok(())
    }
    fn reserve_record(
        &mut self,
        value: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.inner.reserve_record(value, validate)?;
        self.trace.borrow_mut().push(json!({
            "endpoint": self.endpoint,
            "kind": "record",
            "retained_entries": self.inner.seen.len(),
        }));
        Ok(())
    }
}

struct AuthorityFixture {
    a: CompletionEndpoint010,
    b: CompletionEndpoint010,
    control: Controls,
    reads: Trace,
    replay: Trace,
    _tmp: tempfile::TempDir,
}
fn authority_pair(rotated: bool, matching: bool) -> AuthorityFixture {
    let (mut a, mut b, control, tmp) = pair();
    let reads = Rc::new(RefCell::new(Vec::new()));
    let replay = Rc::new(RefCell::new(Vec::new()));
    for (name, endpoint) in [("client", &mut a), ("server", &mut b)] {
        endpoint.registry = Gate::new(
            Config {
                source: "fixture-authority".into(),
                registry: "web:agent.example".into(),
                network: "local".into(),
                blockchain: false,
            },
            Box::new(AuthoritySource {
                control: control.clone(),
                endpoint: name,
                rotated,
                trace: reads.clone(),
            }),
            Box::new(control.clone()),
            Box::new(Journal::open(&tmp.path().join(format!("authority-{name}")), true).unwrap()),
        )
        .unwrap();
        endpoint.replay = Box::new(AuthorityReplay {
            inner: Replay {
                control: control.clone(),
                seen: HashSet::new(),
            },
            endpoint: name,
            trace: replay.clone(),
        });
    }
    if rotated && matching {
        b.kem = EndpointKem::Local(Zeroizing::new(vec![7; 32]));
    }
    AuthorityFixture {
        a,
        b,
        control,
        reads,
        replay,
        _tmp: tmp,
    }
}
fn server_reads(reads: &Trace) -> usize {
    reads
        .borrow()
        .iter()
        .filter(|entry| entry["endpoint"] == "server")
        .count()
}
fn witness(fixture: &AuthorityFixture, kind: &str, request: &[u8], extra: Value) {
    assert!(!request.is_empty() && request.len() <= 32768);
    let mut output = json!({
        "schema": "sage-core-key-authority/1",
        "case": kind,
        "scope": "PREVALIDATED_STATIC_SOURCE_MEMORY_UNIT",
        "source_reads": fixture.reads.borrow().clone(),
        "replay_publications": fixture.replay.borrow().clone(),
        "request_sha256": hex::encode(Sha256::digest(request)),
        "request_b64": B64.encode(request),
        "peer_document_parser": "NOT_EXPOSED",
        "operating_registry": "NOT_BOUND",
        "deployed_custody": "NOT_BOUND",
    });
    for (key, value) in extra.as_object().unwrap() {
        assert!(output.get(key).is_none());
        output[key] = value.clone();
    }
    println!("handshake-key-authority-witness {output}");
}

#[test]
fn handshake_key_authority_positive() {
    for rotated in [false, true] {
        let mut fixture = authority_pair(rotated, true);
        let (mut pending, request) = fixture
            .a
            .start(BOB, &format!("{BOB}#signing-1"), 300)
            .unwrap();
        let (mut server, response) = fixture.b.respond(&request, 300).unwrap();
        let mut client = pending.complete(&mut fixture.a, &response).unwrap();
        let handshake_reads = fixture.reads.borrow().clone();
        let handshake_replay = fixture.replay.borrow().clone();
        let expected_kem = format!("{BOB}#kem-{}", if rotated { 2 } else { 1 });
        for session in [&mut client, &mut server] {
            let tuple = session.tuple();
            assert_eq!(tuple["initDid"], ALICE);
            assert_eq!(tuple["respDid"], BOB);
            assert_eq!(tuple["initKid"], format!("{ALICE}#signing-1"));
            assert_eq!(tuple["respKid"], format!("{BOB}#signing-1"));
            assert_eq!(tuple["kemKid"], expected_kem);
            session.bind_http("https://agent.example/messages").unwrap();
        }
        assert_eq!(client.tuple(), server.tuple());
        assert_eq!(handshake_replay.len(), 2);
        let payload = b"inert core authority request";
        let message = client
            .seal_http_request(&mut fixture.a, payload, 300)
            .unwrap();
        assert_eq!(
            server.open_http_request(&mut fixture.b, &message).unwrap(),
            payload
        );
        let object: Value = serde_json::from_slice(&message.body).unwrap();
        let id = object["id"].as_str().unwrap();
        let reply = server
            .seal_http_response(
                &mut fixture.b,
                id,
                b"inert core authority reply",
                None,
                300,
                200,
            )
            .unwrap();
        let result = client.open_http_response(&mut fixture.a, &reply).unwrap();
        assert!(result.success);
        assert_eq!(result.message_id, id);
        assert_eq!(result.data, b"inert core authority reply");
        assert!(server.open_http_request(&mut fixture.b, &message).is_err());
        assert!(client.open_http_response(&mut fixture.a, &reply).is_err());
        assert!(server_reads(&fixture.reads) > 0);
        let kind = if rotated { "matched-kem-2" } else { "normal" };
        witness(
            &fixture,
            kind,
            &request,
            json!({
                "handshake_source_reads": handshake_reads,
                "handshake_replay_publications": handshake_replay,
                "session_returned": true,
                "completion_b64": B64.encode(&response),
                "tuple": client.tuple(),
                "application_request_b64": B64.encode(&message.body),
                "application_response_b64": B64.encode(&reply.body),
                "application_request_opened": 1,
                "application_response_opened": 1,
                "request_replay_refused": true,
                "response_reuse_refused": true,
            }),
        );
    }
}

#[test]
fn handshake_key_authority_closed_fields() {
    let extras = [
        (
            "didDocument",
            json!({"id": ALICE, "verificationMethod": [], "keyAgreement": []}),
        ),
        ("alsoKnownAs", json!(["did:example:display"])),
        ("equivalentId", json!([BOB])),
        ("canonicalId", json!("did:example:display")),
    ];
    for site in ["outer", "initiation"] {
        for (name, value) in &extras {
            let mut fixture = authority_pair(false, false);
            let (mut pending, request) = fixture
                .a
                .start(BOB, &format!("{BOB}#signing-1"), 300)
                .unwrap();
            let mut outer: Value = serde_json::from_slice(&request).unwrap();
            if site == "outer" {
                outer[*name] = value.clone();
            } else {
                let body = B64.decode(outer["payload"].as_str().unwrap()).unwrap();
                let mut inner: Value = serde_json::from_slice(&body).unwrap();
                inner[*name] = json!(String::from_utf8(canonical(value)).unwrap());
                outer["payload"] = json!(B64.encode(canonical(&inner)));
            }
            outer.as_object_mut().unwrap().remove("signature");
            let changed = signed_with(
                outer,
                b"sage-wire-request|0.10.0\n",
                &SigningKey::from_bytes(&[1; 32]),
            );
            let signed: Raw = serde_json::from_slice(&changed).unwrap();
            let selected = fixture
                .a
                .registry
                .select(ALICE, &format!("{ALICE}#signing-1"), false)
                .unwrap();
            verify_wire(&signed, false, selected.signing()).unwrap();
            assert!(fixture.b.respond(&changed, 300).is_err());
            assert!(fixture.replay.borrow().is_empty());
            assert_eq!(server_reads(&fixture.reads), 0);
            witness(
                &fixture,
                &format!("{site}/{name}"),
                &changed,
                json!({"session_returned": false}),
            );
            pending.close();
        }
    }
}

#[test]
fn handshake_key_authority_current_source() {
    for mode in [
        "local-kem-mismatch",
        "revoke-init",
        "revoke-resp",
        "source-error",
        "local-signing-mismatch",
    ] {
        let mut fixture = authority_pair(mode == "local-kem-mismatch", false);
        let (mut pending, request) = fixture
            .a
            .start(BOB, &format!("{BOB}#signing-1"), 300)
            .unwrap();
        let outer: Value = serde_json::from_slice(&request).unwrap();
        let body = B64.decode(outer["payload"].as_str().unwrap()).unwrap();
        let (inner, _) = d::initiation(&body).unwrap();
        let kem_name = if mode == "local-kem-mismatch" { 2 } else { 1 };
        assert_eq!(inner["kemKid"], format!("{BOB}#kem-{kem_name}"));
        if mode == "local-signing-mismatch" {
            fixture.b.signing = Some(EndpointSigner::Local(SigningKey::from_bytes(&[9; 32])));
        } else if mode != "local-kem-mismatch" {
            fixture.control.0.borrow_mut().mode = mode.into();
        }
        assert!(fixture.b.respond(&request, 300).is_err());
        assert!(fixture.replay.borrow().is_empty());
        assert!(server_reads(&fixture.reads) > 0);
        witness(&fixture, mode, &request, json!({"session_returned": false}));
        pending.close();
    }
}
