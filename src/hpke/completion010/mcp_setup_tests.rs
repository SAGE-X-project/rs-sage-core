use super::*;
use crate::guard010::mcp_setup::{MCPSetup, Phase, SetupClose, SetupIO};
use crate::guard010::{Invalid, Result as GuardResult};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[derive(Default)]
struct Capture {
    wire: Vec<u8>,
    hook: Option<Box<dyn FnMut()>>,
    fail: bool,
}
impl SetupIO for Capture {
    fn send(&mut self, wire: &[u8], _: i64, _: &SetupClose) -> GuardResult<()> {
        if let Some(hook) = self.hook.as_mut() {
            hook();
        }
        if self.fail {
            return Err(Invalid);
        }
        self.wire = wire.to_vec();
        Ok(())
    }
    fn receive(&mut self, _: i64, _: &SetupClose) -> GuardResult<Vec<u8>> {
        Err(Invalid)
    }
}
struct PairIO<'a> {
    server: &'a mut MCPSetup,
    endpoint: &'a mut CompletionEndpoint010,
    reply: Capture,
    tcp: Option<(TcpStream, TcpStream)>,
    prepared: usize,
}
fn send(s: &mut TcpStream, wire: &[u8]) {
    assert!((1..=32768).contains(&wire.len()));
    s.write_all(&(wire.len() as u32).to_be_bytes()).unwrap();
    s.write_all(wire).unwrap();
}
fn receive(s: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 4];
    s.read_exact(&mut header).unwrap();
    let n = u32::from_be_bytes(header) as usize;
    assert!((1..=32768).contains(&n));
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}
impl SetupIO for PairIO<'_> {
    fn send(&mut self, wire: &[u8], _: i64, _: &SetupClose) -> GuardResult<()> {
        let wire = if let Some((client, server)) = self.tcp.as_mut() {
            send(client, wire);
            receive(server)
        } else {
            wire.to_vec()
        };
        let count = &mut self.prepared;
        self.server
            .accept_setup(self.endpoint, &wire, &mut self.reply, &mut || {
                *count += 1;
                Ok(())
            })?;
        if let Some((_, server)) = self.tcp.as_mut() {
            send(server, &self.reply.wire);
        }
        Ok(())
    }
    fn receive(&mut self, _: i64, _: &SetupClose) -> GuardResult<Vec<u8>> {
        Ok(if let Some((client, _)) = self.tcp.as_mut() {
            receive(client)
        } else {
            std::mem::take(&mut self.reply.wire)
        })
    }
}
fn setup_request(id: &str, step: usize) -> Vec<u8> {
    serde_json::to_vec(&match step {
  0=>json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
  1=>json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
  _=>json!({"jsonrpc":"2.0","id":id,"method":"tools/list"})
 }).unwrap()
}
const ID1: &str = "00000000-0000-4000-8000-000000000001";
const ID2: &str = "00000000-0000-4000-8000-000000000002";
#[test]
fn mcp_setup_encrypted_lifecycle_and_tcp_runtime() {
    for tcp in [false, true] {
        let (left, right, mut a, mut b, _, _tmp) = owner_pair();
        let mut client = MCPSetup::new(left, &mut a, "client", "1").unwrap();
        let mut server = MCPSetup::new(right, &mut b, "server", "1").unwrap();
        let sockets = if tcp {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let c =
                TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
                    .unwrap();
            let (s, _) = listener.accept().unwrap();
            for socket in [&c, &s] {
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
            }
            Some((c, s))
        } else {
            None
        };
        let mut io = PairIO {
            server: &mut server,
            endpoint: &mut b,
            reply: Capture::default(),
            tcp: sockets,
            prepared: 0,
        };
        client.run(&mut a, &mut io, &mut || Ok(())).unwrap();
        assert_eq!(io.prepared, 1);
        assert_eq!(client.phase(), Phase::Ready);
        assert_eq!(server.phase(), Phase::Ready);
        assert_eq!(client.history(), server.history());
        assert_eq!(client.history().len(), 2);
        assert!(client
            .run(&mut a, &mut Capture::default(), &mut || Ok(()))
            .is_err());
        assert_eq!(client.phase(), Phase::Closed);
    }
}
#[test]
fn mcp_setup_late_send_and_closure_cannot_publish() {
    for mode in ["close", "deadline", "failure", "panic", "revoked"] {
        let (mut client, right, mut a, mut b, clock, _tmp) = owner_pair();
        let mut server = MCPSetup::new(right, &mut b, "server", "1").unwrap();
        let closer = server.closer();
        let c = clock.clone();
        let hook = move || match mode {
            "close" => {
                let c = closer.clone();
                std::thread::spawn(move || c.close()).join().unwrap();
            }
            "deadline" => c.0.borrow_mut().mono = 30000,
            "panic" => panic!("trusted send"),
            "revoked" => c.0.borrow_mut().mode = "revoke-resp".into(),
            _ => (),
        };
        let mut io = Capture {
            hook: Some(Box::new(hook)),
            fail: mode == "failure",
            ..Default::default()
        };
        let wire = client
            .seal_request(&mut a, &setup_request(ID1, 0), 30)
            .unwrap();
        assert!(
            server
                .accept_setup(&mut b, &wire, &mut io, &mut || Ok(()))
                .is_err(),
            "{mode}"
        );
        assert_eq!(server.phase(), Phase::Closed);
        assert_eq!(server.history(), vec![ID1]);
    }
}
#[test]
fn mcp_setup_reused_ids_and_invalid_authenticated_inner_close() {
    for mode in [
        "duplicate",
        "notification id",
        "wrong method",
        "prepare failure",
    ] {
        let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
        let mut server = MCPSetup::new(right, &mut b, "server", "1").unwrap();
        let mut io = Capture::default();
        let wire = client
            .seal_request(&mut a, &setup_request(ID1, 0), 30)
            .unwrap();
        server
            .accept_setup(&mut b, &wire, &mut io, &mut || Ok(()))
            .unwrap();
        client.open_response(&mut a, &io.wire).unwrap();
        let mut notification: Value = serde_json::from_slice(&setup_request("", 1)).unwrap();
        if mode == "notification id" {
            notification["id"] = json!(ID2);
        }
        if mode == "wrong method" {
            notification["method"] = json!("ping");
        }
        let wire = client
            .seal_request(&mut a, &serde_json::to_vec(&notification).unwrap(), 30)
            .unwrap();
        let result = server.accept_setup(&mut b, &wire, &mut io, &mut || {
            if mode == "prepare failure" {
                Err(Invalid)
            } else {
                Ok(())
            }
        });
        if mode == "duplicate" {
            result.unwrap();
            client.open_response(&mut a, &io.wire).unwrap();
            let wire = client
                .seal_request(&mut a, &setup_request(ID1, 2), 30)
                .unwrap();
            assert!(server
                .accept_setup(&mut b, &wire, &mut io, &mut || Ok(()))
                .is_err());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(server.phase(), Phase::Closed);
        assert!(server.history().contains(&ID1.to_string()));
        if mode == "notification id" {
            assert!(server.history().contains(&ID2.to_string()));
        }
    }
}
#[test]
fn mcp_setup_ids_remain_reserved_for_protected_input() {
    let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
    let mut server = MCPSetup::new(right, &mut b, "server", "1").unwrap();
    let mut io = Capture::default();
    for (id, step) in [(ID1, 0), ("", 1), (ID2, 2)] {
        let wire = client
            .seal_request(&mut a, &setup_request(id, step), 30)
            .unwrap();
        server
            .accept_setup(&mut b, &wire, &mut io, &mut || Ok(()))
            .unwrap();
        client.open_response(&mut a, &io.wire).unwrap();
    }
    assert_eq!(server.phase(), Phase::Ready);
    // This unit fixture has no tool or dispatch callback; repeated setup ID must
    // close before the otherwise invalid protected payload is routed.
    let raw =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":ID1,"method":"tools/call","params":{}}))
            .unwrap();
    let wire = client.seal_request(&mut a, &raw, 30).unwrap();
    assert!(server.open_protected(&mut b, &wire).is_err());
    assert_eq!(server.phase(), Phase::Closed);
    assert_eq!(server.history().len(), 2);
}

#[test]
fn mcp_setup_constructor_cannot_restart_used_or_expired_owner() {
    for expired in [false, true] {
        let (mut left, _right, mut a, _b, clock, _tmp) = owner_pair();
        if expired {
            clock.0.borrow_mut().mono = 30000;
        } else {
            left.seal_request(&mut a, b"prior record", 30).unwrap();
        }
        assert!(MCPSetup::new(left, &mut a, "client", "1").is_err());
    }
}

#[test]
fn mcp_setup_protected_staging_requires_ready_and_fresh_id() {
    for completed in 0..=3 {
        let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
        let mut server = MCPSetup::new(right, &mut b, "server", "1").unwrap();
        let mut io = Capture::default();
        for (id, step) in [(ID1, 0), ("", 1), (ID2, 2)].into_iter().take(completed) {
            let wire = client
                .seal_request(&mut a, &setup_request(id, step), 30)
                .unwrap();
            server
                .accept_setup(&mut b, &wire, &mut io, &mut || Ok(()))
                .unwrap();
            client.open_response(&mut a, &io.wire).unwrap();
        }
        let fixture: Value =
            serde_json::from_str(include_str!("../../guard010/testdata/guard-rpc.json")).unwrap();
        let mut envelope: Value = serde_json::from_slice(
            &hex::decode(fixture["input"]["envelope_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        envelope["intent"]["issuer"] = json!(ALICE);
        envelope["intent"]["recipient"] = json!(BOB);
        envelope["intent"]["keyid"] = json!(format!("{ALICE}#signing-1"));
        envelope["intent"]["created"] = json!(100);
        envelope["intent"]["expires"] = json!(400);
        let bytes = [
            b"sage-execution-intent|0.10.0\0".as_slice(),
            canonical(&envelope["intent"]).as_slice(),
        ]
        .concat();
        envelope["proof"] =
            json!(B64.encode(SigningKey::from_bytes(&[1; 32]).sign(&bytes).to_bytes()));
        let id = "00000000-0000-4000-8000-000000000003";
        let raw = crate::guard010::mcp_request("2025-06-18", id, &canonical(&envelope)).unwrap();
        let wire = client.seal_request(&mut a, &raw, 30).unwrap();
        let result = server.open_protected(&mut b, &wire);
        if completed == 3 {
            assert_eq!(result.unwrap(), raw);
            assert_eq!(server.phase(), Phase::Ready);
            assert_eq!(server.history().len(), 3);
            let wire = client.seal_request(&mut a, &raw, 30).unwrap();
            assert!(server.open_protected(&mut b, &wire).is_err());
            assert_eq!(server.history().len(), 3);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(server.phase(), Phase::Closed);
    }
}
