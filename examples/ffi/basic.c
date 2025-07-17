#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/sage_crypto.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Initialize library
    SageResult result = sage_init();
    if (result != SAGE_SUCCESS) {
        fprintf(stderr, "Failed to initialize SAGE library\n");
        return 1;
    }

    printf("SAGE Crypto Core FFI Example\n");
    printf("Version: %s\n\n", sage_version());

    // Generate Ed25519 key pair
    SageKeyPair* keypair = NULL;
    result = sage_keypair_generate(SAGE_KEY_TYPE_ED25519, &keypair);
    if (result != SAGE_SUCCESS) {
        fprintf(stderr, "Failed to generate key pair: %d\n", result);
        return 1;
    }
    printf("Generated Ed25519 key pair\n");

    // Get key ID
    char key_id[65];
    size_t key_id_len = sizeof(key_id);
    result = sage_keypair_get_key_id(keypair, key_id, &key_id_len);
    if (result == SAGE_SUCCESS) {
        key_id[key_id_len] = '\0';
        printf("Key ID: %s\n", key_id);
    }

    // Export keys
    uint8_t private_key[32];
    uint8_t public_key[32];
    size_t private_len = sizeof(private_key);
    size_t public_len = sizeof(public_key);
    
    result = sage_keypair_export(keypair, private_key, &private_len, public_key, &public_len);
    if (result == SAGE_SUCCESS) {
        print_hex("Private key", private_key, private_len);
        print_hex("Public key", public_key, public_len);
    }

    // Sign a message
    const char* message = "Hello, SAGE!";
    SageSignature* signature = NULL;
    
    result = sage_sign(keypair, (const uint8_t*)message, strlen(message), &signature);
    if (result != SAGE_SUCCESS) {
        fprintf(stderr, "Failed to sign message: %d\n", result);
        sage_keypair_free(keypair);
        return 1;
    }
    printf("\nSigned message: \"%s\"\n", message);

    // Export signature
    uint8_t sig_bytes[64];
    size_t sig_len = sizeof(sig_bytes);
    result = sage_signature_export(signature, sig_bytes, &sig_len);
    if (result == SAGE_SUCCESS) {
        print_hex("Signature", sig_bytes, sig_len);
    }

    // Verify signature
    result = sage_verify_with_keypair(keypair, (const uint8_t*)message, strlen(message), signature);
    if (result == SAGE_SUCCESS) {
        printf("Signature verified successfully!\n");
    } else {
        fprintf(stderr, "Signature verification failed!\n");
    }

    // Test with wrong message
    const char* wrong_message = "Wrong message";
    result = sage_verify_with_keypair(keypair, (const uint8_t*)wrong_message, strlen(wrong_message), signature);
    if (result == SAGE_ERROR_VERIFICATION_FAILED) {
        printf("Wrong message correctly rejected\n");
    }

    // Clean up
    sage_signature_free(signature);
    sage_keypair_free(keypair);

    // Clear sensitive data
    sage_secure_zero(private_key, sizeof(private_key));

    printf("\nFFI test completed successfully!\n");
    return 0;
}