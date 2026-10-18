//! Native SAGE DID views over a complete checked registry observation. This
//! implements projections, not a general DID resolver or an authorization API.
use crate::{
    error::{Error, Result},
    jcs,
    registry010::{ObservedRecord, RecordObserver},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

/// The two explicitly selected DIDP-01 document formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projection {
    /// DID Core 1.0 JSON without a context, JsonWebKey2020.
    Core10,
    /// DID 1.1 JSON with the exact v1.1 context string, JsonWebKey.
    Did11,
}
impl Projection {
    /// Select a bare document format; missing Accept defaults to Core 1.0.
    /// The separate resolution envelope is not a third document format.
    pub fn from_accept(accept: &str) -> Result<Self> {
        match accept {
            "" | "application/did+json" => Ok(Self::Core10),
            "application/did" => Ok(Self::Did11),
            _ => Err(Error::ValidationError("representation.unsupported".into())),
        }
    }
    /// Exact media type of this projection.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Core10 => "application/did+json",
            Self::Did11 => "application/did",
        }
    }
}
/// A document view and RESOLVE-03 metadata, not a DID Resolution execution
/// result. A standard resolver's deactivation and error algorithms are separate.
pub struct DocumentView {
    /// Canonical document bytes for the selected media type.
    pub document: Vec<u8>,
    /// State, version and configured observation metadata without aliases.
    pub metadata: Value,
    /// Exact selected projection media type.
    pub content_type: &'static str,
}
/// Two independently owned views from one checked observation, not a wire envelope.
pub struct DocumentViews {
    /// DID Core 1.0 projection with its observation metadata.
    pub core10: DocumentView,
    /// DID 1.1 projection with the same record version and observation.
    pub did11: DocumentView,
}
/// Observe exactly once through an explicitly configured reader and produce both
/// DIDP-03 views. Each invocation acquires a new owned observation. Failure
/// returns no pair; this does not roll back an observer's durable journal.
/// Source authority, freshness and history remain RecordObserver's contracts.
/// This synchronous API adds no HTTP format or protected-operation authority.
pub fn observe_views(observer: &mut RecordObserver, did: &str) -> Result<DocumentViews> {
    let observed = observer.observe(did)?;
    let core10 = project(&observed, Projection::Core10)?;
    let did11 = project(&observed, Projection::Did11)?;
    Ok(DocumentViews { core10, did11 })
}
fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}
fn str_field<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v.get(name).and_then(Value::as_str).ok_or_else(invalid)
}
/// Project one owned validated record into either DID format. Expired/revoked
/// keys never appear, inactive records have no verification relationships, and
/// services come only from this same record. Views grant no execution authority.
pub fn project(observed: &ObservedRecord, projection: Projection) -> Result<DocumentView> {
    let record = &observed.view;
    let id = str_field(record, "id")?;
    let state = str_field(record, "state")?;
    let mut methods = Vec::new();
    let mut signing = Vec::new();
    let mut agreement = Vec::new();
    for k in record
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
    {
        if state != "active"
            || str_field(k, "state")? != "accepted"
            || k.get("expires")
                .and_then(Value::as_i64)
                .is_some_and(|e| observed.completed().unix >= e)
        {
            continue;
        }
        let alg = str_field(k, "alg")?;
        let material = URL_SAFE_NO_PAD
            .decode(str_field(k, "key")?)
            .map_err(|_| invalid())?;
        let key_id = format!("{id}#{}", str_field(k, "name")?);
        let jwk = match alg {
            "ed25519" | "x25519" => {
                json!({"kty":"OKP","crv":if alg=="ed25519" {"Ed25519"}else{"X25519"},"x":URL_SAFE_NO_PAD.encode(&material)})
            }
            "ecdsa-p256-sha256" | "sage-secp256k1-keccak256" => {
                if material.len() != 65 {
                    return Err(invalid());
                }
                json!({"kty":"EC","crv":if alg=="ecdsa-p256-sha256" {"P-256"}else{"secp256k1"},"x":URL_SAFE_NO_PAD.encode(&material[1..33]),"y":URL_SAFE_NO_PAD.encode(&material[33..65])})
            }
            _ => return Err(invalid()),
        };
        methods.push(json!({"id":key_id,"type":if projection==Projection::Core10 {"JsonWebKey2020"}else{"JsonWebKey"},"controller":id,"publicKeyJwk":jwk}));
        if alg == "x25519" {
            agreement.push(key_id)
        } else {
            signing.push(key_id)
        }
    }
    let services=record.get("services").and_then(Value::as_array).ok_or_else(invalid)?.iter().map(|s| Ok(json!({"id":format!("{id}#{}",str_field(s,"name")?),"type":str_field(s,"type")?,"serviceEndpoint":str_field(s,"uri")?}))).collect::<Result<Vec<_>>>()?;
    let mut doc = json!({"id":id,"verificationMethod":methods,"service":services});
    if projection == Projection::Did11 {
        doc["@context"] = json!("https://www.w3.org/ns/did/v1.1")
    }
    if !signing.is_empty() {
        doc["authentication"] = json!(signing);
        doc["assertionMethod"] = json!(signing)
    }
    if !agreement.is_empty() {
        doc["keyAgreement"] = json!(agreement)
    }
    let data = jcs::canonical(&serde_json::to_vec(&doc).map_err(|_| invalid())?)?;
    if data.len() > 262144 {
        return Err(Error::ValidationError("size.exceeded".into()));
    }
    let metadata = json!({"deactivated":state=="deactivated","versionId":str_field(record,"version")?,"sage":{"state":state,"controller":str_field(record,"controller")?,"observedAt":observed.observed_at(),"source":observed.source(),"observedTime":observed.completed().unix}});
    Ok(DocumentView {
        document: data,
        metadata,
        content_type: projection.media_type(),
    })
}
