//! Test-only local fixture process; no RPC, TLS or operation authorization.
use sage_crypto_core::{
    didsource010::{project, Projection},
    error::Result,
    registry010::{
        Clock, Config, Journal, RecordObserver, RecordOrigin, RecordReader, RecordSnapshot, Stamp,
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Read},
};
struct Reader(RecordSnapshot);
impl RecordReader for Reader {
    fn read_record(&mut self, _: &str) -> Result<RecordSnapshot> {
        Ok(self.0.clone())
    }
}
struct Time;
impl Clock for Time {
    fn now(&mut self) -> Result<Stamp> {
        Ok(Stamp {
            mono_ms: 100,
            unix: 101,
        })
    }
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(262145).read_to_end(&mut bytes)?;
    if bytes.len() > 262144 {
        return Err("fixture exceeds input bound".into());
    }
    let input: Value = serde_json::from_slice(&bytes)?;
    let cases = input["cases"].as_array().ok_or("missing cases")?;
    let dir = tempfile::tempdir()?;
    let mut results = BTreeMap::new();
    for (i, case) in cases.iter().enumerate() {
        let r = &case["record"];
        let did = r["id"].as_str().ok_or("missing id")?;
        let web = did.contains(":web:");
        let cfg = Config {
            source: "fixture-view-only-source".into(),
            registry: if web {
                "web:agents.example.com".into()
            } else {
                "eip155:11155111:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
            },
            network: "fixture-network".into(),
            blockchain: !web,
        };
        let h = "a".repeat(64);
        let snapshot = RecordSnapshot {
            source: cfg.source.clone(),
            registry: cfg.registry.clone(),
            network: cfg.network.clone(),
            data: serde_json::to_vec(&if web {
                json!({"record":r,"issued":100,"expires":105})
            } else {
                r.clone()
            })?,
            origin: if web {
                RecordOrigin::AuthenticatedWeb
            } else {
                RecordOrigin::FinalizedBlock {
                    block_hash: h.clone(),
                    record_block_hash: h.clone(),
                    keys_block_hash: h.clone(),
                    services_block_hash: h,
                    finalized: true,
                }
            },
            acquired_ms: 100,
            ready: true,
            validated: true,
            conflicting: false,
        };
        let mut o = RecordObserver::new(
            cfg,
            Box::new(Reader(snapshot)),
            Box::new(Time),
            Box::new(Journal::open(&dir.path().join(i.to_string()), true)?),
        )?;
        let observed = o.observe(did)?;
        let mut views = BTreeMap::new();
        for (name, p) in [("core10", Projection::Core10), ("did11", Projection::Did11)] {
            let v = project(&observed, p)?;
            views.insert(name,json!({"document":String::from_utf8(v.document)?,"contentType":v.content_type,"metadata":v.metadata}));
        }
        results.insert(case["name"].as_str().ok_or("missing case name")?, views);
    }
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}
