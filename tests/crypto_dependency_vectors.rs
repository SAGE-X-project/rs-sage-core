//! Fixed published values protect cryptographic dependency migrations.
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

#[test]
fn p256_rfc6979_sample_preserves_public_keys_and_low_s_signatures() {
    use sage_crypto_core::crypto::{
        p256::P256KeyPair, KeyPair, KeyType, Signature, Signer, Verifier,
    };

    // Public test material from RFC 6979, Appendix A.2.5 (SHA-256, "sample").
    // SAGE normalizes the published high S to q - S without changing r.
    let private =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public = hex::decode(concat!(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    ))
    .unwrap();
    let expected = hex::decode(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
    ))
    .unwrap();
    let published = hex::decode(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ))
    .unwrap();
    let pair = P256KeyPair::from_private_key_bytes(&private).unwrap();
    let core = KeyPair::from_private_key_bytes(KeyType::P256, &private).unwrap();
    assert_eq!(pair.public_key_bytes(), public);
    assert_eq!(core.public_key_bytes(), public);
    assert_eq!(pair.sign(b"sample").unwrap(), expected);
    assert_eq!(core.sign(b"sample").unwrap().to_bytes(), expected);
    for bytes in [&expected, &published] {
        pair.verify(b"sample", bytes).unwrap();
        let signature = Signature::from_bytes(KeyType::P256, bytes).unwrap();
        core.verify(b"sample", &signature).unwrap();
        assert!(pair.verify(b"different message", bytes).is_err());
        assert!(core.verify(b"different message", &signature).is_err());
    }
}

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
