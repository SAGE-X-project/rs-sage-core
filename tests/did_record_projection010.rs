//! Native projections exercise public observation boundaries, never authorization.
use sage_crypto_core::{
    didsource010::{observe_views, project, Projection},
    error::{Error, Result},
    registry010::{
        Clock, Config, Journal, RecordObserver, RecordOrigin, RecordReader, RecordSnapshot, Stamp,
    },
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

const EIP: &str = "did:sage:eip155:11155111:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:billing-bot";
const WEB: &str = "did:sage:web:agents.example.com:billing-bot";
fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/did-record-projections010.json")).unwrap()
}
fn record(name: &str) -> Value {
    fixtures()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["record"]
        .clone()
}
fn cfg(web: bool) -> Config {
    Config {
        source: "fixture-view-only-source".into(),
        registry: if web {
            "web:agents.example.com".into()
        } else {
            "eip155:11155111:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
        },
        network: "fixture-network".into(),
        blockchain: !web,
    }
}
fn snap(record: &Value, web: bool) -> RecordSnapshot {
    let c = cfg(web);
    let hash = "a".repeat(64);
    RecordSnapshot {
        source: c.source,
        registry: c.registry,
        network: c.network,
        data: serde_json::to_vec(&if web {
            json!({"record":record,"issued":100,"expires":105})
        } else {
            record.clone()
        })
        .unwrap(),
        origin: if web {
            RecordOrigin::AuthenticatedWeb
        } else {
            RecordOrigin::FinalizedBlock {
                block_hash: hash.clone(),
                record_block_hash: hash.clone(),
                keys_block_hash: hash.clone(),
                services_block_hash: hash,
                finalized: true,
            }
        },
        acquired_ms: 100,
        ready: true,
        validated: true,
        conflicting: false,
    }
}
struct Reader {
    reads: Arc<AtomicUsize>,
    values: VecDeque<Result<RecordSnapshot>>,
}
impl RecordReader for Reader {
    fn read_record(&mut self, _: &str) -> Result<RecordSnapshot> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.values
            .pop_front()
            .unwrap_or_else(|| Err(Error::Other("lost source".into())))
    }
}
struct Times(VecDeque<Result<Stamp>>);
impl Clock for Times {
    fn now(&mut self) -> Result<Stamp> {
        self.0
            .pop_front()
            .unwrap_or_else(|| Err(Error::Other("lost clock".into())))
    }
}
fn observer(
    c: Config,
    s: Vec<Result<RecordSnapshot>>,
    times: Vec<(i64, i64)>,
    path: &std::path::Path,
    create: bool,
    reads: Arc<AtomicUsize>,
) -> Result<RecordObserver> {
    RecordObserver::new(
        c,
        Box::new(Reader {
            reads,
            values: s.into(),
        }),
        Box::new(Times(
            times
                .into_iter()
                .map(|(mono_ms, unix)| Ok(Stamp { mono_ms, unix }))
                .collect(),
        )),
        Box::new(Journal::open(path, create)?),
    )
}
fn check(
    s: RecordSnapshot,
    times: Vec<(i64, i64)>,
    did: &str,
) -> Result<sage_crypto_core::registry010::ObservedRecord> {
    let dir = tempfile::tempdir().unwrap();
    observer(
        cfg(did == WEB),
        vec![Ok(s)],
        times,
        &dir.path().join("journal"),
        true,
        Arc::new(AtomicUsize::new(0)),
    )?
    .observe(did)
}
fn normal() -> Vec<(i64, i64)> {
    vec![(100, 101), (100, 101), (100, 101)]
}
fn code<T>(result: Result<T>, expected: &str) {
    match result {
        Err(Error::ValidationError(c)) => assert_eq!(c, expected),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("expected {expected}"),
    }
}

#[test]
fn both_profiles_and_projections_match_independent_public_fixtures() {
    let f = fixtures();
    assert_eq!(f["basis"], "06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b");
    for case in f["cases"].as_array().unwrap() {
        let r = &case["record"];
        let did = r["id"].as_str().unwrap();
        let web = did == WEB;
        let observed = check(snap(r, web), normal(), did).unwrap();
        assert_eq!(observed.record_json(), serde_json::to_vec(r).unwrap());
        assert_eq!(observed.source(), "fixture-view-only-source");
        assert_eq!(observed.completed().unix, 101);
        for (p, name) in [(Projection::Core10, "core10"), (Projection::Did11, "did11")] {
            let v = project(&observed, p).unwrap();
            let expected = &case["expected"][name];
            assert_eq!(
                String::from_utf8(v.document).unwrap(),
                expected["document"].as_str().unwrap(),
                "{} {name}",
                case["name"]
            );
            assert_eq!(v.metadata, expected["metadata"]);
            assert_eq!(v.content_type, expected["contentType"]);
        }
    }
}
#[test]
fn media_selection_is_exact_and_does_not_claim_http_negotiation() {
    for a in ["", "application/did+json"] {
        assert_eq!(Projection::from_accept(a).unwrap(), Projection::Core10)
    }
    assert_eq!(
        Projection::from_accept("application/did").unwrap(),
        Projection::Did11
    );
    for a in [
        "*/*",
        "application/did+ld+json",
        "application/did-resolution",
        "application/did; charset=utf-8",
        "text/plain",
    ] {
        code(Projection::from_accept(a), "representation.unsupported")
    }
}
#[test]
fn reader_diagnostics_survive_without_inventing_authenticated_absence() {
    for web in [false, true] {
        for (err, expected) in [
            (
                Error::ValidationError("size.exceeded".into()),
                "size.exceeded",
            ),
            (
                Error::ValidationError("record.invalid".into()),
                "record.invalid",
            ),
            (
                Error::ValidationError("record.stale".into()),
                "record.stale",
            ),
            (
                Error::ValidationError("not-found".into()),
                "record.unreachable",
            ),
            (
                Error::Other("private transport detail".into()),
                "record.unreachable",
            ),
            (
                Error::NotFound("peer says absent".into()),
                "record.unreachable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut o = observer(
                cfg(web),
                vec![Err(err)],
                normal(),
                &dir.path().join("j"),
                true,
                Arc::new(AtomicUsize::new(0)),
            )
            .unwrap();
            code(o.observe(if web { WEB } else { EIP }), expected);
        }
    }
}
#[test]
fn malformed_identifiers_never_reach_a_reader() {
    let dir = tempfile::tempdir().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut o = observer(
        cfg(false),
        vec![],
        normal(),
        &dir.path().join("j"),
        true,
        reads.clone(),
    )
    .unwrap();
    for id in [
        "did:sage:eip155:01:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:a",
        "did:sage:web:agents.example.com:billing-bot",
        "did:sage:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:a",
        "did:sage:eip155:11155111:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:a#key",
        "did:other:a",
    ] {
        assert!(o.observe(id).is_err());
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}
#[test]
fn constructor_requires_canonical_trust_and_profile_origin_agreement() {
    for change in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(false);
        match change {
            0 => c.source.clear(),
            1 => c.registry.push(':'),
            2 => c.network = "a\nb".into(),
            3 => c.source = "a\0b".into(),
            4 => c.source = "é".into(),
            5 => c.blockchain = false,
            6 => c.registry = "web:EXAMPLE.com".into(),
            _ => c.network = "x".repeat(257),
        };
        assert!(observer(
            c,
            vec![],
            normal(),
            &dir.path().join("j"),
            true,
            Arc::new(AtomicUsize::new(0))
        )
        .is_err());
    }
}
#[test]
fn source_flags_and_each_finalized_component_fail_closed() {
    for change in 0..13 {
        let mut s = snap(&record("eip155-active"), false);
        let expected = match change {
            0 => {
                s.ready = false;
                "record.unreachable"
            }
            1 => {
                s.source = "other".into();
                "record.unreachable"
            }
            2 => {
                s.registry = "other".into();
                "record.unreachable"
            }
            3 => {
                s.network = "other".into();
                "record.unreachable"
            }
            4 => {
                s.validated = false;
                "record.stale"
            }
            5 => {
                s.conflicting = true;
                "record.stale"
            }
            6 => {
                s.origin = RecordOrigin::AuthenticatedWeb;
                "record.stale"
            }
            _ => {
                if let RecordOrigin::FinalizedBlock {
                    block_hash,
                    record_block_hash,
                    keys_block_hash,
                    services_block_hash,
                    finalized,
                } = &mut s.origin
                {
                    match change {
                        7 => *finalized = false,
                        8 => *block_hash = "A".repeat(64),
                        9 => *record_block_hash = "b".repeat(64),
                        10 => *keys_block_hash = "b".repeat(64),
                        11 => *services_block_hash = "b".repeat(64),
                        _ => *block_hash = "a".repeat(63),
                    }
                }
                "record.stale"
            }
        };
        code(check(s, normal(), EIP), expected);
    }
    let mut web = snap(&record("web-active"), true);
    web.origin = snap(&record("eip155-active"), false).origin;
    code(check(web, normal(), WEB), "record.stale");
}
#[test]
fn observation_clocks_cover_read_storage_boundaries_and_exact_deadline() {
    let r = record("eip155-active");
    for (times, code_) in [
        (vec![], "record.unreachable"),
        (vec![(100, 101)], "record.unreachable"),
        (vec![(100, 101), (100, 101)], "record.unreachable"),
        (vec![(-1, 101)], "record.unreachable"),
        (vec![(100, -1)], "record.unreachable"),
        (vec![(100, 9007199254740992)], "record.unreachable"),
        (vec![(100, 101), (99, 101)], "record.stale"),
        (vec![(100, 101), (100, 100)], "record.stale"),
        (vec![(100, 101), (5101, 101)], "record.stale"),
        (vec![(100, 101), (100, 101), (5101, 101)], "record.stale"),
    ] {
        code(check(snap(&r, false), times, EIP), code_)
    }
    let mut s = snap(&r, false);
    s.acquired_ms = 101;
    code(check(s, normal(), EIP), "record.stale");
    assert!(check(
        snap(&r, false),
        vec![(100, 101), (5100, 101), (5100, 101)],
        EIP
    )
    .is_ok());
}
#[test]
fn invalid_complete_records_cannot_become_documents() {
    let r = record("eip155-active");
    for change in 0..14 {
        let mut v = r.clone();
        match change {
            0 => v["controller"] = json!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            1 => v["controller"] = json!("operator"),
            2 => v["extra"] = json!(true),
            3 => v["keys"][0]["proof"]["value"] = json!("AA"),
            4 => v["version"] = json!("01"),
            5 => v["keys"][1]["proof"]["signer"] = json!(format!("{EIP}#missing")),
            6 => v["id"] = json!(WEB),
            7 => v["services"][0]["uri"] = json!("http://agents.example.com"),
            8 => v["keys"][0]["expires"] = json!(-1),
            9 => v["keys"][0]["expires"] = json!(100.5),
            10 => v["keys"][0]["alg"] = json!("rsa"),
            11 => v["state"] = json!("unknown"),
            12 => v["keys"][0]["state"] = json!("invalid"),
            _ => v["keys"].as_array_mut().unwrap().reverse(),
        };
        code(check(snap(&v, false), normal(), EIP), "record.invalid")
    }
    for raw in [
        vec![255],
        vec![],
        b"{} {}".to_vec(),
        b"{\"x\":1,\"x\":2}".to_vec(),
        [vec![0xef, 0xbb, 0xbf], serde_json::to_vec(&r).unwrap()].concat(),
        format!("{}{}", "[".repeat(40), "]".repeat(40)).into_bytes(),
    ] {
        let mut s = snap(&r, false);
        s.data = raw;
        code(check(s, normal(), EIP), "record.invalid")
    }
    for (web, size) in [(false, 65537), (true, 69633)] {
        let mut s = snap(&r, web);
        s.data = vec![b' '; size];
        code(
            check(s, normal(), if web { WEB } else { EIP }),
            "size.exceeded",
        )
    }
}
#[test]
fn web_envelope_is_rechecked_after_storage_and_exact_integer_spellings_work() {
    let r = record("web-active");
    code(
        check(
            snap(&r, true),
            vec![(100, 101), (100, 101), (100, 105)],
            WEB,
        ),
        "record.invalid",
    );
    for issued in ["100.0", "1e2"] {
        let mut s = snap(&r, true);
        s.data = format!("{{\"record\":{r},\"issued\":{issued},\"expires\":105}}").into_bytes();
        assert_eq!(check(s, normal(), WEB).unwrap().observed_at(), &json!(100))
    }
    let mut s = snap(&r, true);
    s.data = format!("{{\"record\":{r},\"issued\":-1,\"expires\":4}}").into_bytes();
    code(
        check(s, vec![(100, 0), (100, 0), (100, 0)], WEB),
        "record.invalid",
    );
    for expiry in ["100.0", "1e2"] {
        let mut s = snap(&r, true);
        let mut v = r.clone();
        v["keys"][0]["expires"] = json!("expiry-placeholder");
        s.data = json!({"record":v,"issued":100,"expires":105})
            .to_string()
            .replace("\"expiry-placeholder\"", expiry)
            .into_bytes();
        let view = project(&check(s, normal(), WEB).unwrap(), Projection::Core10).unwrap();
        let doc: Value = serde_json::from_slice(&view.document).unwrap();
        assert_eq!(doc["verificationMethod"].as_array().unwrap().len(), 3);
    }
}
#[test]
fn restart_preserves_rollback_equal_version_conflict_and_terminal_state() {
    for change in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        let reads = Arc::new(AtomicUsize::new(0));
        let mut first = record("eip155-active");
        if change == 2 {
            first["state"] = json!("deactivated")
        }
        let mut o = observer(
            cfg(false),
            vec![Ok(snap(&first, false))],
            normal(),
            &path,
            true,
            reads.clone(),
        )
        .unwrap();
        o.observe(EIP).unwrap();
        drop(o);
        let mut next = first.clone();
        match change {
            0 => next["version"] = json!("0"),
            1 => next["services"] = json!([]),
            _ => {
                next["version"] = json!("2");
                next["state"] = json!("active")
            }
        };
        // Use a valid previous version after advancing the first to 2.
        if change == 0 {
            first["version"] = json!("2");
            let mut o = observer(
                cfg(false),
                vec![Ok(snap(&first, false))],
                normal(),
                &path,
                false,
                reads.clone(),
            )
            .unwrap();
            o.observe(EIP).unwrap();
            drop(o);
            next["version"] = json!("1");
        }
        let mut o = observer(
            cfg(false),
            vec![Ok(snap(&next, false))],
            normal(),
            &path,
            false,
            reads,
        )
        .unwrap();
        code(o.observe(EIP), "record.stale");
    }
}

#[test]
fn all_signing_keys_expired_still_resolve_but_cannot_authorize() {
    for web in [false, true] {
        for kem_live in [false, true] {
            let mut r = record(if web { "web-active" } else { "eip155-active" });
            for k in r["keys"].as_array_mut().unwrap() {
                k["expires"] = json!(if kem_live && k["alg"] == "x25519" {
                    102
                } else {
                    100
                });
            }
            let observed = check(snap(&r, web), normal(), if web { WEB } else { EIP }).unwrap();
            for projection in [Projection::Core10, Projection::Did11] {
                let view = project(&observed, projection).unwrap();
                let doc: Value = serde_json::from_slice(&view.document).unwrap();
                assert!(doc.get("authentication").is_none());
                assert!(doc.get("assertionMethod").is_none());
                assert_eq!(
                    doc["verificationMethod"].as_array().unwrap().len(),
                    usize::from(kem_live)
                );
                assert_eq!(doc.get("keyAgreement").is_some(), kem_live);
            }
        }
    }
}

#[test]
fn paired_views_read_once_and_match_independent_public_fixtures() {
    let f = fixtures();
    for case in f["cases"].as_array().unwrap() {
        let r = &case["record"];
        let did = r["id"].as_str().unwrap();
        let web = did == WEB;
        let dir = tempfile::tempdir().unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut o = observer(
            cfg(web),
            vec![Ok(snap(r, web))],
            normal(),
            &dir.path().join("j"),
            true,
            reads.clone(),
        )
        .unwrap();
        let views = observe_views(&mut o, did).unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        for (v, name) in [(views.core10, "core10"), (views.did11, "did11")] {
            let expected = &case["expected"][name];
            assert_eq!(
                String::from_utf8(v.document).unwrap(),
                expected["document"].as_str().unwrap()
            );
            assert_eq!(v.metadata, expected["metadata"]);
            assert_eq!(v.content_type, expected["contentType"].as_str().unwrap());
        }
    }
}

#[test]
fn paired_views_follow_versions_and_own_their_storage() {
    let first_record = record("eip155-active");
    let mut second_record = record("eip155-deactivated");
    second_record["version"] = json!("8");
    let mut second_snapshot = snap(&second_record, false);
    let hash = "b".repeat(64);
    second_snapshot.origin = RecordOrigin::FinalizedBlock {
        block_hash: hash.clone(),
        record_block_hash: hash.clone(),
        keys_block_hash: hash.clone(),
        services_block_hash: hash.clone(),
        finalized: true,
    };
    second_snapshot.acquired_ms = 101;
    let dir = tempfile::tempdir().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut times = normal();
    times.extend([(101, 102), (101, 102), (101, 102), (102, 103)]);
    let mut o = observer(
        cfg(false),
        vec![Ok(snap(&first_record, false)), Ok(second_snapshot)],
        times,
        &dir.path().join("j"),
        true,
        reads.clone(),
    )
    .unwrap();
    let mut first = observe_views(&mut o, EIP).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let first_expected = first.did11.metadata.clone();
    first.core10.document[0] = b'x';
    first.core10.metadata["sage"]["controller"] = json!("changed");
    assert_eq!(first.did11.document[0], b'{');
    assert_eq!(first.did11.metadata, first_expected);
    let second = observe_views(&mut o, EIP).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    let f = fixtures();
    let expected = &f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "eip155-deactivated")
        .unwrap()["expected"];
    for (v, name) in [(second.core10, "core10"), (second.did11, "did11")] {
        assert_eq!(
            String::from_utf8(v.document).unwrap(),
            expected[name]["document"].as_str().unwrap()
        );
        let mut metadata = expected[name]["metadata"].clone();
        metadata["versionId"] = json!("8");
        metadata["sage"]["observedAt"] = json!(hash);
        metadata["sage"]["observedTime"] = json!(102);
        assert_eq!(v.metadata, metadata);
        assert_eq!(v.content_type, expected[name]["contentType"].as_str().unwrap());
    }
    code(observe_views(&mut o, EIP), "record.unreachable");
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

#[test]
fn paired_views_keep_observer_refusal_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut o = observer(
        cfg(false),
        vec![Err(Error::Other("fixture unavailable".into()))],
        normal(),
        &dir.path().join("j"),
        true,
        reads.clone(),
    )
    .unwrap();
    assert!(observe_views(&mut o, "did:other:a").is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    code(observe_views(&mut o, EIP), "record.unreachable");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    for flag in ["unready", "unvalidated"] {
        let dir = tempfile::tempdir().unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut snapshot = snap(&record("eip155-active"), false);
        if flag == "unready" {
            snapshot.ready = false;
        } else {
            snapshot.validated = false;
        }
        let mut o = observer(
            cfg(false),
            vec![Ok(snapshot)],
            normal(),
            &dir.path().join("j"),
            true,
            reads.clone(),
        )
        .unwrap();
        code(
            observe_views(&mut o, EIP),
            if flag == "unready" {
                "record.unreachable"
            } else {
                "record.stale"
            },
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
