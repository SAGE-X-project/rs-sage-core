use sage_crypto_core::guard010::{original_commitment, RootCapture};

#[test]
fn external_host_can_construct_a_bounded_root_capture() {
    let original = vec![b"trusted root input".to_vec()];
    assert_eq!(
        original_commitment(&original).unwrap(),
        "4dfd470e686f50c56d34a34147d753c21c7de8e012111afcd6c98f84817c8014"
    );
    assert!(RootCapture::new(&original, "00000000-0000-4000-8000-000000000002").is_ok());
    assert!(RootCapture::new(&original, "not-a-request-id").is_err());
}
