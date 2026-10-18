use super::*;
use super::super::owner010::application010::{copy_metadata, read_metadata};
const TARGET: &str = "https://agent.example/messages";

type ApplicationPair = (HTTPApplicationOwner010, HTTPApplicationOwner010, CompletionEndpoint010, CompletionEndpoint010, Controls, tempfile::TempDir);
fn application_pair(http: bool, target: &str) -> ApplicationPair {
    let (mut a, mut b, controls, tmp) = pair();
    let (left,right) = if http {
        a.bind_http(target).unwrap(); b.bind_http(target).unwrap();
        let (mut pending,request) = a.start_http(BOB,&format!("{BOB}#signing-1"),300).unwrap();
        let (right,response) = b.respond_http(&request,300).unwrap();
        (pending.complete_http(&mut a,&response).unwrap(),right)
    } else {
        let (mut pending,request) = a.start(BOB,&format!("{BOB}#signing-1"),300).unwrap();
        let (right,response) = b.respond(&request,300).unwrap();
        (pending.complete(&mut a,&response).unwrap(),right)
    };
    (left.into_http_application(&a,target).unwrap(),right.into_http_application(&b,target).unwrap(),a,b,controls,tmp)
}
fn metadata(value: &str) -> BTreeMap<String,String> { BTreeMap::from([("note".into(),value.into())]) }

#[test]
fn http_application_round_trips() {
    for http in [false,true] { for kind in ["absent","empty","a2a","unicode","error"] {
        let (mut left,mut right,mut a,mut b,c,_tmp)=application_pair(http,TARGET);
        let fields = match kind {
            "absent"=>None,"empty"=>Some(BTreeMap::new()),"a2a"=>Some(BTreeMap::from([("a2a_version".into(),"1.0".into()),("a2a_extensions".into(),"https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension".into())])),
            _=>Some(metadata("한글 😀 \0 \\\""))
        };
        let request=left.seal_request(&mut a,b"inert request",fields.as_ref(),300).unwrap();
        let body:Value=serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body.get("metadata").is_some(),fields.is_some());
        let view=right.open_request(&mut b,&request).unwrap();
        assert_eq!(view.payload(),b"inert request"); assert_eq!(view.metadata(),fields.as_ref());
        assert_eq!(view.sender(),ALICE); assert_eq!(view.recipient(),BOB); assert_eq!(view.key_id(),format!("{ALICE}#signing-1"));
        assert_eq!(view.id(),body["id"].as_str().unwrap());assert_eq!(view.context_id(),body["context_id"].as_str().unwrap());assert_eq!(view.session_id(),body["session_id"].as_str().unwrap());
        assert!(right.open_request(&mut b,&request).is_err());
        let reply_fields=metadata("independent response");let error=(kind=="error").then_some("policy_denied");let status=if error.is_some(){403}else{200};
        let reply=right.seal_response(&mut b,view.id(),b"inert response",Some(&reply_fields),error,300,status).unwrap();
        let response=left.open_response(&mut a,&reply).unwrap();
        assert_eq!(response.data(),b"inert response");assert_eq!(response.metadata(),Some(&reply_fields));assert_eq!(response.in_reply_to(),view.id());assert_eq!(response.success(),error.is_none());assert_eq!(response.error(),error.unwrap_or(""));
        assert_eq!(response.envelope().sender(),BOB);assert_eq!(response.envelope().recipient(),ALICE);assert_eq!(response.envelope().key_id(),format!("{BOB}#signing-1"));
        assert!(left.open_response(&mut a,&reply).is_err());assert!(right.seal_response(&mut b,view.id(),b"",None,None,300,200).is_err());
        assert_eq!(left.participants().unwrap(),(ALICE.into(),BOB.into()));assert_eq!(right.participants().unwrap(),(BOB.into(),ALICE.into()));
        left.check(&mut a).unwrap();assert_eq!(left.local_now(&mut a).unwrap(),0);assert_eq!(left.observe(&mut a).unwrap(),0);
        assert_eq!(c.0.borrow().records,2);
        let mut clone=response.metadata().unwrap().clone();clone.insert("note".into(),"mutated copy".into());assert_eq!(response.metadata(),Some(&reply_fields));
        println!("http-application-control roundtrip/http={http}/{kind}: accepted exact request/response and replay controls");
    }}
}
#[test]
fn http_application_metadata_admission() {
    for (text,valid) in [
        (r#"{}"#,true),(r#"{"a":""}"#,true),(r#"{"note":"한글 😀"}"#,true),(r#"{"note":"\uD83D\uDE00"}"#,true),(r#"{"note":"\\ud800"}"#,true),
        ("null",false),("[]",false),("true",false),(r#"{"a":null}"#,false),(r#"{"a":1}"#,false),(r#"{"a":{}}"#,false),(r#"{"a":[]}"#,false),
        (r#"{"a":"one","a":"two"}"#,false),(r#"{"a":"one","\u0061":"two"}"#,false),(r#"{"A":"x"}"#,false),(r#"{"1a":"x"}"#,false),(r#"{"a-":"x"}"#,false),(r#"{"":"x"}"#,false),
        (r#"{"a":"\ud800"}"#,false),(r#"{"a":"\udc00"}"#,false),(r#"{"a":"\ud800\ud800"}"#,false)
    ] {
        let raw=RawValue::from_string(text.to_owned());
        let accepted = match raw { Ok(raw) => read_metadata(Some(raw.as_ref())).is_ok(), Err(_) => false };
        assert_eq!(accepted,valid,"{text}");
    }
    assert!(read_metadata(None).unwrap().is_none());
    for size in [32usize,33] {
        let map:BTreeMap<_,_>=(0..size).map(|i|(format!("k{i}"),"x".into())).collect();
        assert_eq!(copy_metadata(Some(&map)).is_ok(),size==32);
        let raw=RawValue::from_string(serde_json::to_string(&map).unwrap()).unwrap();assert_eq!(read_metadata(Some(&raw)).is_ok(),size==32);
        assert_eq!(copy_metadata(Some(&BTreeMap::from([("a".repeat(size),"x".into())]))).is_ok(),size==32);
    }
    for value in ["x".repeat(1024),"é".repeat(512),"😀".repeat(256)] {
        assert!(copy_metadata(Some(&metadata(&value))).is_ok());assert!(copy_metadata(Some(&metadata(&(value+"x")))).is_err());
    }
    for size in [995usize,996] {
        let map=BTreeMap::from([("a".into(),"x".repeat(1024)),("b".into(),"x".repeat(1024)),("c".into(),"x".repeat(1024)),("d".into(),"x".repeat(size))]);
        assert_eq!(canonical(&map).len(),4096+size-995);assert_eq!(copy_metadata(Some(&map)).is_ok(),size==995);
    }
    println!("http-application-control admission: strict object, unique keys, Unicode and byte/JCS bounds");
}
#[test]
fn http_application_refuses_unavailable_authority() {
    for mode in ["revoke-init","revoke-resp","source-error","store-error","store-delay","clock-error"] { for response in [false,true] {
        let (mut left,mut right,mut a,mut b,c,_tmp)=application_pair(true,TARGET);
        let info=BTreeMap::from([("did_document".into(),"display only".into()),("canonical_id".into(),"did:example:informational".into())]);
        let mut message=left.seal_request(&mut a,b"inert request",Some(&info),300).unwrap();
        if response { let view=right.open_request(&mut b,&message).unwrap();message=right.seal_response(&mut b,view.id(),b"inert response",Some(&info),None,300,200).unwrap(); }
        let before=c.0.borrow().records;c.0.borrow_mut().mode=mode.into();
        if response { assert!(left.open_response(&mut a,&message).is_err()); } else { assert!(right.open_request(&mut b,&message).is_err()); }
        assert_eq!(c.0.borrow().records,before);
        println!("http-application-control authority/{mode}/response={response}: no returned view or accepted record");
    }}
}
#[test]
fn http_application_legacy_request_refuses_metadata() {
    for fields in [BTreeMap::new(),metadata("inert")] {
        let (mut a,mut b,c,_tmp)=pair();
        let (mut pending,hello)=a.start(BOB,&format!("{BOB}#signing-1"),300).unwrap();let (mut right,reply)=b.respond(&hello,300).unwrap();let left=pending.complete(&mut a,&reply).unwrap();
        let mut owner=left.into_http_application(&a,TARGET).unwrap();right.bind_http(TARGET).unwrap();
        let wire=owner.seal_request(&mut a,b"inert",Some(&fields),300).unwrap();let before=c.0.borrow().records;
        assert!(right.open_http_request(&mut b,&wire).is_err());assert_eq!(right.state(),"RESPONSE_SENT");assert_eq!(c.0.borrow().records,before);
        // Failed old admission marks record_used in Rust. Do not pretend an
        // already-used session can be transferred or restore its history.
        assert!(right.into_http_application(&b,TARGET).is_err());
    }
}
#[test]
fn http_application_legacy_response_refuses_metadata() {
    for fields in [BTreeMap::new(),metadata("inert")] {
        let (mut a,mut b,c,_tmp)=pair();let(mut pending,hello)=a.start(BOB,&format!("{BOB}#signing-1"),300).unwrap();let(right,reply)=b.respond(&hello,300).unwrap();let mut left=pending.complete(&mut a,&reply).unwrap();
        left.bind_http(TARGET).unwrap();let mut right=right.into_http_application(&b,TARGET).unwrap();
        let q=left.seal_http_request(&mut a,b"inert request",300).unwrap();let request=right.open_request(&mut b,&q).unwrap();
        let r=right.seal_response(&mut b,request.id(),b"inert response",Some(&fields),None,300,200).unwrap();let before=c.0.borrow().records;
        assert!(left.open_http_response(&mut a,&r).is_err());assert_eq!(left.state(),"ESTABLISHED");assert!(!left.sent.get(request.id()).unwrap().terminal);assert_eq!(c.0.borrow().records,before);
        let q=left.seal_http_request(&mut a,b"inert positive",300).unwrap();let request=right.open_request(&mut b,&q).unwrap();let r=right.seal_response(&mut b,request.id(),b"inert positive response",None,None,300,200).unwrap();assert_eq!(left.open_http_response(&mut a,&r).unwrap().data,b"inert positive response");
    }
}

// These owned-key changes are confined to unit tests, never network tooling.
#[test]
fn http_application_metadata_crypto_bindings() {
    for response in [false,true] { for kind in ["null","duplicate","inner","outer","aead","recipient","session","request-hash"] {
        if !response && kind=="request-hash" {continue;}
        let(mut left,mut right,mut a,mut b,c,_tmp)=application_pair(true,TARGET);
        let request=left.seal_request(&mut a,b"inert request",Some(&metadata("original")),300).unwrap();
        let original=if response{let view=right.open_request(&mut b,&request).unwrap();right.seal_response(&mut b,view.id(),b"inert response",Some(&metadata("original")),None,300,200).unwrap()}else{request.clone()};
        let mut bad=original.clone();let mut fields:Value=serde_json::from_slice(&original.body).unwrap();
        fields["metadata"]=json!({"note":"changed"});
        match kind {
            "null"=>fields["metadata"]=Value::Null,
            "recipient"=>fields["recipient"]=json!(if response{BOB}else{ALICE}),
            "session"=>fields["session_id"]=json!(B64.encode([0;16])),
            "request-hash"=>fields["request_hash"]=json!(B64.encode([0;32])),
            _=>{}
        }
        bad.body=serde_json::to_vec(&fields).unwrap();
        if kind=="duplicate"{bad.body=String::from_utf8(bad.body).unwrap().replace(r#""metadata":{"note":"changed"}"#,r#""metadata":{"note":"one","\u006eote":"two"}"#).into_bytes();assert_ne!(bad.body,serde_json::to_vec(&fields).unwrap());}
        let sender=if response{&b}else{&a};
        if ["aead","recipient","session","request-hash","outer"].contains(&kind){
            fields.as_object_mut().unwrap().remove("signature");
            let domain=if response{b"sage-wire-response|0.10.0\n".as_slice()}else{b"sage-wire-request|0.10.0\n".as_slice()};
            bad.body=signed_with(fields,domain,sender.local_signing_key());
            let signed:Raw=serde_json::from_slice(&bad.body).unwrap();let key=Key{name:"signing-1".into(),alg:"ed25519".into(),material:hex::encode(sender.local_signing_key().verifying_key().to_bytes()),state:"accepted".into(),expires:None};
            verify_wire(&signed,response,&key).unwrap();
        }
        if kind=="outer"||kind=="null"||kind=="duplicate"{
            use base64::engine::general_purpose::STANDARD;
            bad.headers.iter_mut().find(|p|p[0]=="content-digest").unwrap()[1]=format!("sha-256=:{}:",STANDARD.encode(Sha256::digest(&bad.body)));
        }else{record010::http010::resign_test(&mut bad,sender,response.then_some(&request));}
        let before=c.0.borrow().records;
        if response {assert!(left.open_response(&mut a,&bad).is_err());let view=left.open_response(&mut a,&original).unwrap();assert_eq!(view.data(),b"inert response");}
        else{assert!(right.open_request(&mut b,&bad).is_err());let view=right.open_request(&mut b,&original).unwrap();assert_eq!(view.payload(),b"inert request");}
        assert_eq!(c.0.borrow().records,before+1);
        println!("http-application-control binding/{kind}/response={response}: refused without consuming valid sequence");
    }}
}
fn application_aad(fields:&Raw)->Vec<u8>{canonical(&fields.iter().filter(|(k,_)|!["payload","data","signature"].contains(&k.as_str())).collect::<BTreeMap<_,_>>())}
fn application_sequence(message:&HTTPMessage010,field:&str)->u64{let fields:Value=serde_json::from_slice(&message.body).unwrap();let record=B64.decode(fields[field].as_str().unwrap()).unwrap();u64::from_be_bytes(record[..8].try_into().unwrap())}
#[test]
fn http_application_complete_aad_boundaries(){
    for response in [false,true]{
        let(mut left,mut right,mut a,mut b,_c,_tmp)=application_pair(true,TARGET);
        let first=left.seal_request(&mut a,b"",Some(&BTreeMap::new()),300).unwrap();let request=right.open_request(&mut b,&first).unwrap();
        let control=if response{right.seal_response(&mut b,request.id(),b"",Some(&BTreeMap::new()),None,300,200).unwrap()}else{first};
        let fields:Raw=serde_json::from_slice(&control.body).unwrap();let budget=4033-application_aad(&fields).len();
        let mut metadata:BTreeMap<String,String>=["a","b","c","d"].into_iter().map(|k|(k.into(),String::new())).collect();
        let mut remaining=budget-(canonical(&metadata).len()-2);
        for key in ["a","b","c","d"]{let n=remaining.min(1024);metadata.insert(key.into(),"x".repeat(n));remaining-=n;}assert_eq!(remaining,0);
        let mut excessive=metadata.clone();excessive.get_mut("d").unwrap().push('x');
        let accepted=if response{
            let q=left.seal_request(&mut a,b"",None,300).unwrap();let request=right.open_request(&mut b,&q).unwrap();
            assert!(right.seal_response(&mut b,request.id(),b"",Some(&excessive),None,300,200).is_err());
            let accepted=right.seal_response(&mut b,request.id(),b"",Some(&metadata),None,300,200).unwrap();assert_eq!(application_sequence(&accepted,"data"),1);left.open_response(&mut a,&accepted).unwrap();accepted
        }else{
            assert!(left.seal_request(&mut a,b"",Some(&excessive),300).is_err());let accepted=left.seal_request(&mut a,b"",Some(&metadata),300).unwrap();assert_eq!(application_sequence(&accepted,"payload"),1);right.open_request(&mut b,&accepted).unwrap();accepted
        };
        let fields:Raw=serde_json::from_slice(&accepted.body).unwrap();assert_eq!(application_aad(&fields).len(),4033);
        println!("http-application-control aad/response={response}: exact4033 accepted,4034 refused before sequence");
    }
}
#[test]
fn http_application_transfer_and_retirement(){
    for mode in ["invalid-target","mismatched-target","used","closed","wrong-endpoint","retired"]{
        let(mut a,mut b,_c,_tmp)=pair();let(mut p,q)=a.start(BOB,&format!("{BOB}#signing-1"),300).unwrap();let(_right,r)=b.respond(&q,300).unwrap();let mut left=p.complete(&mut a,&r).unwrap();
        match mode{"mismatched-target"=>left.bind_http("https://other.example/messages").unwrap(),"used"=>{left.seal_request(&mut a,b"inert",300).unwrap();},"closed"=>left.close(),"retired"=>a.close(),_=>{}}
        let endpoint=if mode=="wrong-endpoint"{&b}else{&a};let target=if mode=="invalid-target"{"http://agent.example/messages"}else{TARGET};assert!(left.into_http_application(endpoint,target).is_err());
    }
    let(mut left,mut right,mut a,mut b,_c,_tmp)=application_pair(true,TARGET);a.close();assert!(left.seal_request(&mut a,b"",None,300).is_err());assert!(left.participants().is_err());
    right.close();assert!(right.check(&mut b).is_err());assert!(right.participants().is_err());
    let(mut left,_,_,mut b,_,_tmp)=application_pair(false,TARGET);assert!(left.check(&mut b).is_err());assert!(left.participants().is_err());
}
#[test]
fn http_application_owned_inputs(){
    let(mut left,mut right,mut a,mut b,_c,_tmp)=application_pair(false,TARGET);let mut payload=b"original".to_vec();let mut fields=metadata("original");
    let wire=left.seal_request(&mut a,&payload,Some(&fields),300).unwrap();payload[0]=b'X';fields.insert("note".into(),"changed".into());let view=right.open_request(&mut b,&wire).unwrap();assert_eq!(view.payload(),b"original");assert_eq!(view.metadata(),Some(&metadata("original")));
    let mut result=b"original response".to_vec();let mut fields=metadata("original result");let wire=right.seal_response(&mut b,view.id(),&result,Some(&fields),None,300,200).unwrap();result[0]=b'X';fields.clear();let view=left.open_response(&mut a,&wire).unwrap();assert_eq!(view.data(),b"original response");assert_eq!(view.metadata(),Some(&metadata("original result")));
}

struct ApplicationPostClock { controls: Controls, accepted_before: u64 }
impl Clock for ApplicationPostClock {
    fn now(&mut self)->Result<Stamp>{
        if self.controls.0.borrow().records>self.accepted_before {return Err(bad());}
        self.controls.now()
    }
}
#[test]
fn http_application_post_acceptance_mirror_failure(){
    for response in [false,true]{
        let(mut left,mut right,mut a,mut b,c,_tmp)=application_pair(true,TARGET);
        let request=left.seal_request(&mut a,b"inert request",None,300).unwrap();
        let message=if response{let view=right.open_request(&mut b,&request).unwrap();right.seal_response(&mut b,view.id(),b"inert response",None,None,300,200).unwrap()}else{request};
        let before=c.0.borrow().records;
        if response{
            a.clock=Box::new(ApplicationPostClock{controls:c.clone(),accepted_before:before});
            assert!(left.open_response(&mut a,&message).is_err());assert!(left.participants().is_err());
            a.clock=Box::new(c.clone());assert!(left.open_response(&mut a,&message).is_err());assert!(left.check(&mut a).is_err());
        }else{
            b.clock=Box::new(ApplicationPostClock{controls:c.clone(),accepted_before:before});
            assert!(right.open_request(&mut b,&message).is_err());assert!(right.participants().is_err());
            b.clock=Box::new(c.clone());assert!(right.open_request(&mut b,&message).is_err());assert!(right.check(&mut b).is_err());
        }
        assert_eq!(c.0.borrow().records,before+1);
        println!("http-application-control post-mirror/response={response}: no returned view, acceptance retained, owner retired");
    }
}
struct ApplicationCountingClock { controls:Controls, calls:Rc<RefCell<usize>> }
impl Clock for ApplicationCountingClock {fn now(&mut self)->Result<Stamp>{*self.calls.borrow_mut()+=1;self.controls.now()}}
#[test]
fn http_application_invalid_outgoing_before_clock(){
    let(mut left,mut right,mut a,mut b,c,_tmp)=application_pair(true,TARGET);
    let request=left.seal_request(&mut a,b"inert",None,300).unwrap();let view=right.open_request(&mut b,&request).unwrap();
    let left_calls=Rc::new(RefCell::new(0));let right_calls=Rc::new(RefCell::new(0));
    a.clock=Box::new(ApplicationCountingClock{controls:c.clone(),calls:left_calls.clone()});b.clock=Box::new(ApplicationCountingClock{controls:c,calls:right_calls.clone()});
    for invalid in [BTreeMap::from([("Invalid".into(),"x".into())]),metadata(&"x".repeat(1025))]{
        assert!(left.seal_request(&mut a,b"",Some(&invalid),300).is_err());assert!(right.seal_response(&mut b,view.id(),b"",Some(&invalid),None,300,200).is_err());
    }
    assert_eq!(*left_calls.borrow(),0);assert_eq!(*right_calls.borrow(),0);
}

#[cfg(not(target_arch = "wasm32"))]
mod owned_tls {
    use super::*;
    use rustls::pki_types::{CertificateDer,PrivateKeyDer,PrivatePkcs8KeyDer,ServerName};
    use rustls::{ClientConfig,ClientConnection,RootCertStore,ServerConfig,ServerConnection,StreamOwned};
    use std::io::{Read,Write};
    use std::net::{TcpListener,TcpStream};
    use std::sync::{mpsc,Arc};
    use std::time::Duration;
    const ROOT:&[u8]=include_bytes!("../../../../tests/fixtures/http-application-root010.der");
    const LEAF:&[u8]=include_bytes!("../../../../tests/fixtures/http-application-leaf010.der");

    // A closed, benign test fixture, not a production HTTP parser or transport.
    fn write_fixture(stream:&mut impl Write,message:&HTTPMessage010,request:bool){
        let mut head=if request {"POST /messages HTTP/1.1\r\n".to_owned()}else{format!("HTTP/1.1 {} OK\r\n",message.status)};
        if request{head.push_str(&format!("Host: {}\r\n",message.authority));}
        for [name,value] in &message.headers{assert!(!name.eq_ignore_ascii_case("content-length"));head.push_str(&format!("{name}: {value}\r\n"));}
        head.push_str(&format!("Content-Length: {}\r\n\r\n",message.body.len()));assert!(head.len()<=32768&&message.body.len()<=32768);
        stream.write_all(head.as_bytes()).unwrap();stream.write_all(&message.body).unwrap();stream.flush().unwrap();
    }
    fn read_fixture(stream:&mut impl Read,request:bool)->HTTPMessage010{
        let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n"){assert!(head.len()<32768);let mut one=[0];stream.read_exact(&mut one).unwrap();head.push(one[0]);}
        let head=String::from_utf8(head).unwrap();let mut lines=head[..head.len()-4].split("\r\n");let start=lines.next().unwrap().split(' ').collect::<Vec<_>>();assert_eq!(start.len(),3);
        let headers=lines.map(|line|{let(name,value)=line.split_once(':').unwrap();[name.to_ascii_lowercase(),value.trim_start_matches(' ').to_owned()]}).collect::<Vec<_>>();
        let length=headers.iter().find(|p|p[0]=="content-length").unwrap()[1].parse::<usize>().unwrap();assert!(length<=32768);let mut body=vec![0;length];stream.read_exact(&mut body).unwrap();
        if request{let authority=headers.iter().find(|p|p[0]=="host").unwrap()[1].clone();HTTPMessage010{method:start[0].into(),target:format!("https://{authority}{}",start[1]),authority,status:0,headers,body}}
        else{HTTPMessage010{method:String::new(),target:String::new(),authority:String::new(),status:start[1].parse().unwrap(),headers,body}}
    }
    #[test]
    fn http_application_owned_tls_round_trip(){
        for unavailable in [false,true]{
            let _=rustls::crypto::ring::default_provider().install_default();
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();let address=listener.local_addr().unwrap();let target=format!("https://localhost:{}/messages",address.port());
            let client_socket=TcpStream::connect_timeout(&address,Duration::from_secs(2)).unwrap();let(server_socket,_)=listener.accept().unwrap();drop(listener);
            for socket in [&client_socket,&server_socket]{socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();}
            let mut roots=RootCertStore::empty();roots.add(CertificateDer::from(ROOT.to_vec())).unwrap();let client_config=ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            // Deterministic public test seed 09 repeated32, never deployment custody.
            let mut key=vec![0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20];key.extend_from_slice(&[9;32]);
            let server_config=ServerConfig::builder().with_no_client_auth().with_single_cert(vec![CertificateDer::from(LEAF.to_vec())],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))).unwrap();
            let(mut left,mut right,mut a,mut b,c,_tmp)=application_pair(true,&target);
            let fields=BTreeMap::from([("a2a_version".into(),"1.0".into())]);let request=left.seal_request(&mut a,b"inert TLS request",Some(&fields),300).unwrap();
            if unavailable{c.0.borrow_mut().mode="source-error".into();}
            let(request_tx,request_rx)=mpsc::channel();let(response_tx,response_rx)=mpsc::channel();let(result_tx,result_rx)=mpsc::channel();
            let server=std::thread::spawn(move||{let mut stream=StreamOwned::new(ServerConnection::new(Arc::new(server_config)).unwrap(),server_socket);let actual=read_fixture(&mut stream,true);request_tx.send(actual).unwrap();let response=response_rx.recv_timeout(Duration::from_secs(5)).unwrap();write_fixture(&mut stream,&response,false);});
            let client=std::thread::spawn(move||{let mut stream=StreamOwned::new(ClientConnection::new(Arc::new(client_config),ServerName::try_from("localhost").unwrap()).unwrap(),client_socket);write_fixture(&mut stream,&request,true);result_tx.send(read_fixture(&mut stream,false)).unwrap();});
            let actual=request_rx.recv_timeout(Duration::from_secs(5)).unwrap();assert_eq!(actual.target,target);let mut handled=0;
            let response=if unavailable{assert!(right.open_request(&mut b,&actual).is_err());HTTPMessage010{method:String::new(),target:String::new(),authority:String::new(),status:503,headers:vec![],body:b"inert unavailable".to_vec()}}
            else{let view=right.open_request(&mut b,&actual).unwrap();assert_eq!(view.payload(),b"inert TLS request");assert_eq!(view.metadata(),Some(&fields));handled+=1;right.seal_response(&mut b,view.id(),b"inert TLS response",Some(&metadata("response")),None,300,200).unwrap()};
            response_tx.send(response).unwrap();let actual=result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if unavailable{assert_eq!(actual.status,503);assert!(left.open_response(&mut a,&actual).is_err());assert_eq!(handled,0);assert_eq!(c.0.borrow().records,0);}
            else{let view=left.open_response(&mut a,&actual).unwrap();assert_eq!(view.data(),b"inert TLS response");assert_eq!(view.metadata(),Some(&metadata("response")));assert_eq!(view.envelope().sender(),BOB);assert_eq!(handled,1);assert_eq!(c.0.borrow().records,2);}
            client.join().unwrap();server.join().unwrap();println!("http-application-control owned-tls/unavailable={unavailable}: authenticated transport facts, inert handler count {handled}");
        }
    }
}

#[test]
fn http_application_size_and_argument_refusals(){
    let(mut left,mut right,mut a,mut b,_c,_tmp)=application_pair(true,TARGET);
    assert!(left.seal_request(&mut a,&vec![0;16349],None,300).is_err());
    assert!(left.seal_request(&mut a,b"",None,0).is_err());assert!(left.seal_request(&mut a,b"",None,301).is_err());
    let payload=vec![42;16348];let request=left.seal_request(&mut a,&payload,Some(&BTreeMap::new()),300).unwrap();let view=right.open_request(&mut b,&request).unwrap();assert_eq!(view.payload(),payload);
    assert!(right.seal_response(&mut b,view.id(),&vec![0;16349],None,None,300,200).is_err());
    for status in [199,204,600]{assert!(right.seal_response(&mut b,view.id(),b"",None,None,300,status).is_err());}
    assert!(right.seal_response(&mut b,"not-an-id",b"",None,None,300,200).is_err());
    let reply=right.seal_response(&mut b,view.id(),&payload,Some(&BTreeMap::new()),None,300,200).unwrap();assert_eq!(left.open_response(&mut a,&reply).unwrap().data(),payload);
    for mut message in [request.clone(),reply.clone()]{
        message.body=vec![0;32769];assert!(right.open_request(&mut b,&message).is_err());assert!(left.open_response(&mut a,&message).is_err());
        message.body.clear();message.headers=vec![["note".into(),"inert".into()];257];assert!(right.open_request(&mut b,&message).is_err());assert!(left.open_response(&mut a,&message).is_err());
    }
}
