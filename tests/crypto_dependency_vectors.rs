//! Fixed published values protect the HMAC/HKDF dependency migration.
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

#[test]
fn hmac_sha256_rfc4231_case_one() {
    // https://www.rfc-editor.org/rfc/rfc4231#section-4.2
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x0b; 20]).unwrap();
    mac.update(b"Hi There");
    assert_eq!(mac.clone().finalize().into_bytes().as_slice(), expected);
    assert!(mac.clone().verify_slice(&expected).is_ok());
    let mut changed = expected;
    changed[0] ^= 1;
    assert!(mac.clone().verify_slice(&changed).is_err());
    assert!(mac.verify_slice(&changed[..31]).is_err());
}

#[test]
fn hkdf_sha256_rfc5869_case_one() {
    // https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &[0x0b; 22]);
    assert_eq!(
        hex::encode(prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let expected = hex::decode(concat!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865",
    ))
    .unwrap();
    let mut output = [0; 42];
    hkdf.expand(&info, &mut output).unwrap();
    assert_eq!(output.as_slice(), expected);
    let mut from_prk = [0; 42];
    Hkdf::<Sha256>::from_prk(&prk)
        .unwrap()
        .expand(&info, &mut from_prk)
        .unwrap();
    assert_eq!(from_prk, output);
}
