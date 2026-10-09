use super::*;
use ed25519_dalek::Signer;

/// In-process stand-ins for external custody; not protected services.
struct TestSigner {
    key: SigningKey,
    mode: &'static str,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Ed25519Custody010 for TestSigner {
    fn public_key(&mut self) -> Result<[u8; 32]> {
        Ok(self.key.verifying_key().to_bytes())
    }
    fn sign(&mut self, m: &[u8]) -> Result<[u8; 64]> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.mode {
            "error" => Err(bad()),
            "panic" => panic!("inert custody failure"),
            "other-key" => Ok(SigningKey::from_bytes(&[9; 32]).sign(m).to_bytes()),
            _ => Ok(self.key.sign(m).to_bytes()),
        }
    }
}
struct TestKem {
    key: [u8; 32],
    mode: &'static str,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl X25519Custody010 for TestKem {
    fn public_key(&mut self) -> Result<[u8; 32]> {
        Ok(x25519(self.key, X25519_BASEPOINT_BYTES))
    }
    fn ecdh(&mut self, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.mode {
            "error" => Err(bad()),
            "zero" => Ok(Zeroizing::new([0; 32])),
            "panic" => panic!("inert custody failure"),
            _ => Ok(Zeroizing::new(x25519(self.key, *peer))),
        }
    }
}
type Counter = std::sync::Arc<std::sync::atomic::AtomicUsize>;
fn counter() -> Counter {
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))
}
fn count(c: &Counter) -> usize {
    c.load(std::sync::atomic::Ordering::SeqCst)
}

/// Replace Bob in a fixture pair with a protected endpoint built on the same
/// gate and clock fixtures.
fn protected_bob(
    controls: &Controls,
    tmp: &tempfile::TempDir,
    sign_mode: &'static str,
    kem_key: [u8; 32],
    kem_mode: &'static str,
) -> (CompletionEndpoint010, Counter, Counter) {
    let gate = Gate::new(
        Config {
            source: "fixture-authority".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            blockchain: false,
        },
        Box::new(controls.clone()),
        Box::new(controls.clone()),
        Box::new(Journal::open(&tmp.path().join("protected-bob"), true).unwrap()),
    )
    .unwrap();
    let (signs, ecdhs) = (counter(), counter());
    let e = CompletionEndpoint010::new_protected(
        BOB,
        &format!("{BOB}#signing-1"),
        Box::new(TestSigner {
            key: SigningKey::from_bytes(&[2; 32]),
            mode: sign_mode,
            calls: signs.clone(),
        }),
        Some(Box::new(TestKem {
            key: kem_key,
            mode: kem_mode,
            calls: ecdhs.clone(),
        })),
        gate,
        Box::new(controls.clone()),
        Box::new(Replay {
            control: controls.clone(),
            seen: HashSet::new(),
        }),
    )
    .unwrap();
    (e, signs, ecdhs)
}

#[test]
fn protected_endpoint_holds_no_private_keys() {
    let (mut a, _, controls, tmp) = pair();
    let (mut b, signs, ecdhs) = protected_bob(&controls, &tmp, "", [3; 32], "");
    assert!(matches!(b.signing, Some(EndpointSigner::Custody { .. })));
    assert!(matches!(b.kem, EndpointKem::Custody { .. }));
    let (mut p, request) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
    let (mut s, response) = b.respond(&request, 300).unwrap();
    let mut i = p.complete(&mut a, &response).unwrap();
    assert_eq!((count(&signs), count(&ecdhs)), (2, 1));
    let sealed = i.seal_request(&mut a, b"2+3", 300).unwrap();
    assert_eq!(s.open_request(&mut b, &sealed).unwrap(), b"2+3");
}

#[test]
fn protected_endpoint_custody_failures_emit_nothing() {
    for (sign_mode, kem_key, kem_mode) in [
        ("error", [3; 32], ""),
        ("panic", [3; 32], ""),
        ("other-key", [3; 32], ""),
        ("", [3; 32], "error"),
        ("", [3; 32], "zero"),
        ("", [3; 32], "panic"),
        ("", [4; 32], ""),
    ] {
        let (mut a, _, controls, tmp) = pair();
        let (mut b, _, ecdhs) = protected_bob(&controls, &tmp, sign_mode, kem_key, kem_mode);
        let (_p, request) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = b.respond(&request, 300);
        std::panic::set_hook(hook);
        assert!(
            result.is_err(),
            "custody failure produced a completion: sign={sign_mode} kem={kem_mode}"
        );
        if kem_key == [4; 32] {
            assert_eq!(count(&ecdhs), 0, "unregistered KEM custody was used");
        }
    }
}

#[test]
fn closed_protected_endpoint_never_uses_custody() {
    let (mut a, _, controls, tmp) = pair();
    let (mut b, signs, ecdhs) = protected_bob(&controls, &tmp, "", [3; 32], "");
    b.close();
    let (_p, request) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
    assert!(b.respond(&request, 300).is_err());
    assert_eq!((count(&signs), count(&ecdhs)), (0, 0));
}
