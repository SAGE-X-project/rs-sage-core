use super::*;

fn base() -> Entry {
    Entry {
        issuer: "issuer".into(),
        recipient: "executor".into(),
        call_id: "call".into(),
        nonce: "nonce".into(),
        expires: 1000,
        intent_hex: "7b7d".into(),
        state: "RESERVED".into(),
        result_hex: String::new(),
    }
}
#[test]
fn shared_vectors() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/execution-ledger010.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let mut l = Ledger::open(&path, true).unwrap();
        for step in case["steps"].as_array().unwrap() {
            let q = &step["request"];
            let mut changed = false;
            let mut found = None;
            let result = match q["action"].as_str().unwrap() {
                "commit" => l
                    .commit(serde_json::from_value(q["entry"].clone()).unwrap())
                    .map(|v| changed = v),
                "lookup" => l
                    .lookup(
                        q["issuer"].as_str().unwrap(),
                        q["call_id"].as_str().unwrap(),
                    )
                    .map(|v| found = v),
                "reopen" => l
                    .close()
                    .and_then(|_| Ledger::open(&path, false))
                    .map(|v| l = v),
                _ => panic!("unknown action"),
            };
            assert_eq!(
                serde_json::json!({"ok":result.is_ok(),"changed":changed,"entry":found}),
                step["expected"],
                "{}: {}",
                case["id"],
                q
            );
        }
        l.close().unwrap();
    }
}
#[test]
fn storage_failures() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("ledger");
    assert!(Ledger::open(&p, false).is_err());
    let mut l = Ledger::open(&p, true).unwrap();
    assert!(Ledger::open(&p, false).is_err());
    assert!(Ledger::open(&p, true).is_err());
    l.rows = MAX_ROWS;
    assert!(l.commit(base()).is_err());
    l.rows = 0;
    l.size = MAX_SIZE;
    assert!(l.commit(base()).is_err());
    l.size = HEADER.len() as u64;
    // Replace only this owned test handle with a read-only descriptor to inject IO failure.
    l.file = Some(File::open(&p).unwrap());
    assert!(l.commit(base()).is_err());
    assert!(l.lookup("issuer", "call").is_err());
    assert!(l.close().is_err());
    assert!(d.path().join("ledger.lock").exists());
    for suffix in ["{", "\n", "{}\n"] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ledger");
        let mut raw = HEADER.to_vec();
        raw.extend_from_slice(suffix.as_bytes());
        fs::write(&p, raw).unwrap();
        assert!(Ledger::open(&p, false).is_err());
    }
}
#[test]
fn concurrent_reservation() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(
        Ledger::open(&d.path().join("ledger"), true).unwrap(),
    ));
    let threads: Vec<_> = (0..20)
        .map(|_| {
            let l = ledger.clone();
            std::thread::spawn(move || l.lock().unwrap().commit(base()).unwrap())
        })
        .collect();
    let count = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|v| *v)
        .count();
    assert_eq!(count, 1);
    ledger.lock().unwrap().close().unwrap();
}

#[test]
fn terminal_write_failure() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("ledger");
    let mut l = Ledger::open(&p, true).unwrap();
    let mut e = base();
    l.commit(e.clone()).unwrap();
    e.state = "EXECUTING".into();
    l.commit(e.clone()).unwrap();
    l.file = Some(File::open(&p).unwrap());
    e.state = "COMPLETED".into();
    e.result_hex = "7b7d".into();
    assert!(l.commit(e).is_err());
    assert!(l.close().is_err());
    fs::remove_file(d.path().join("ledger.lock")).unwrap();
    let mut l = Ledger::open(&p, false).unwrap();
    let e = l.lookup("issuer", "call").unwrap().unwrap();
    assert_eq!(e.state, "UNKNOWN");
    assert!(e.result_hex.is_empty());
    l.close().unwrap();
}
#[test]
fn reject_noncanonical_history() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let row = serde_json::to_string(&base()).unwrap();
    for body in [
        format!("{row}\n{row}\n"),
        format!(" {row}\n"),
        format!("{},\"extra\":1}}\n", &row[..row.len() - 1]),
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ledger");
        let mut raw = HEADER.to_vec();
        raw.extend_from_slice(body.as_bytes());
        fs::write(&p, raw).unwrap();
        assert!(Ledger::open(&p, false).is_err());
    }
}

#[test]
fn reserve_reads_all_existing_states_without_transitions() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    for state in ["RESERVED", "EXECUTING", "COMPLETED", "REJECTED", "UNKNOWN"] {
        let d = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(&d.path().join("journal"), true).unwrap();
        let e = base();
        assert!(l.reserve(e.clone()).unwrap().1);
        let mut want = e.clone();
        if matches!(state, "EXECUTING" | "COMPLETED") {
            want.state = "EXECUTING".into();
            l.commit(want.clone()).unwrap();
        }
        want.state = state.into();
        if matches!(state, "COMPLETED" | "REJECTED") {
            want.result_hex = "7b7d".into();
        }
        l.commit(want.clone()).unwrap();
        let (size, rows) = (l.size, l.rows);
        let (got, changed) = l.reserve(e.clone()).unwrap();
        assert!(!changed);
        assert_eq!(got, want);
        assert_eq!((l.size, l.rows), (size, rows));
        let mut bad = e;
        bad.nonce = "other".into();
        assert!(l.reserve(bad).is_err());
        l.close().unwrap();
    }
}
#[test]
fn failed_reservation_does_not_publish_identity() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("journal");
    let mut l = Ledger::open(&p, true).unwrap();
    l.file = Some(File::open(&p).unwrap());
    assert!(l.reserve(base()).is_err());
    assert!(!l.entries.contains_key(&("issuer".into(), "call".into())));
    assert!(l.failed);
    assert!(l.close().is_err());
    assert!(p.with_extension("lock").exists());
}
