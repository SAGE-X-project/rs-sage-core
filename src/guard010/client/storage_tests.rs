use super::super::client_tests::{setup, Services};
use super::*;
struct Expiry(Services, usize);
impl Authority for Expiry {
    fn now(&mut self) -> Result<i64> {
        self.1 += 1;
        if self.1 == 4 {
            Ok(1700000300)
        } else {
            self.0.now()
        }
    }
    fn active_key(&mut self, i: &str, k: &str) -> Result<[u8; 32]> {
        self.0.active_key(i, k)
    }
}
#[test]
fn failed_storage_and_late_expiry_do_not_release_output() {
    for capacity in [false, true] {
        let (_d, p, c, s, v) = setup();
        if !capacity {
            c.state.lock().unwrap().services.result_authority = Box::new(Expiry(s.clone(), 0));
        }
        let t = c.begin("00000000-0000-4000-8000-000000000001").unwrap();
        // Offline capacity injection; no production bypass API.
        if capacity {
            c.state.lock().unwrap().rows = 1023;
        }
        let raw = hex::decode(v["results"]["completed"].as_str().unwrap()).unwrap();
        assert!(c.accept(&t, &raw).is_err());
        if capacity {
            let state = c.state.lock().unwrap();
            assert!(state.failed && state.terminal.is_empty());
            drop(state);
            assert!(c.close().is_err());
        } else {
            assert!(!c.state.lock().unwrap().terminal.is_empty());
            c.close().unwrap();
            let raw = hex::decode(v["input"]["envelope_hex"].as_str().unwrap()).unwrap();
            let c = Client::open(&p, false, &raw, s.config()).unwrap();
            assert!(c.begin("00000000-0000-4000-8000-000000000002").is_err());
            c.close().unwrap();
        }
    }
}
