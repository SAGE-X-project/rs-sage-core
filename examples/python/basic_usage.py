#!/usr/bin/env python3
"""
Basic usage example for SAGE Crypto Core Python bindings
"""

import ctypes
from ctypes import Structure, POINTER, c_char_p, c_int, c_void_p, c_size_t
import platform
import sys

# Load the library
def load_sage_library():
    if platform.system() == "Windows":
        return ctypes.CDLL("sage_crypto_core.dll")
    elif platform.system() == "Darwin":
        return ctypes.CDLL("libsage_crypto_core.dylib")
    else:
        return ctypes.CDLL("libsage_crypto_core.so")

try:
    lib = load_sage_library()
except OSError as e:
    print(f"Failed to load SAGE Crypto Core library: {e}")
    print("Make sure the library is installed and in your system PATH/LD_LIBRARY_PATH")
    sys.exit(1)

# Constants
SAGE_SUCCESS = 0
SAGE_KEY_TYPE_ED25519 = 0
SAGE_KEY_TYPE_SECP256K1 = 1

# Opaque handle types
class SageKeyPair(Structure):
    pass

class SageSignature(Structure):
    pass

# Function signatures
lib.sage_init.argtypes = []
lib.sage_init.restype = c_int

lib.sage_keypair_generate.argtypes = [c_int, POINTER(POINTER(SageKeyPair))]
lib.sage_keypair_generate.restype = c_int

lib.sage_keypair_sign_string.argtypes = [POINTER(SageKeyPair), c_char_p, POINTER(POINTER(SageSignature))]
lib.sage_keypair_sign_string.restype = c_int

lib.sage_keypair_verify_string.argtypes = [POINTER(SageKeyPair), c_char_p, POINTER(SageSignature)]
lib.sage_keypair_verify_string.restype = c_int

lib.sage_signature_to_hex.argtypes = [POINTER(SageSignature)]
lib.sage_signature_to_hex.restype = c_char_p

lib.sage_keypair_free.argtypes = [POINTER(SageKeyPair)]
lib.sage_keypair_free.restype = None

lib.sage_signature_free.argtypes = [POINTER(SageSignature)]
lib.sage_signature_free.restype = None

lib.sage_get_last_error.argtypes = []
lib.sage_get_last_error.restype = c_char_p

# Error handling
class SageError(Exception):
    pass

def check_result(result):
    if result != SAGE_SUCCESS:
        error_msg = lib.sage_get_last_error()
        raise SageError(error_msg.decode('utf-8') if error_msg else "Unknown error")

# Python wrapper classes
class KeyPair:
    def __init__(self, key_type=SAGE_KEY_TYPE_ED25519):
        self.handle = POINTER(SageKeyPair)()
        result = lib.sage_keypair_generate(key_type, ctypes.byref(self.handle))
        check_result(result)
    
    def __del__(self):
        if hasattr(self, 'handle') and self.handle:
            lib.sage_keypair_free(self.handle)
    
    def sign_string(self, message):
        signature_handle = POINTER(SageSignature)()
        message_bytes = message.encode('utf-8')
        result = lib.sage_keypair_sign_string(
            self.handle, 
            message_bytes, 
            ctypes.byref(signature_handle)
        )
        check_result(result)
        return Signature(signature_handle)
    
    def verify_string(self, message, signature):
        message_bytes = message.encode('utf-8')
        result = lib.sage_keypair_verify_string(
            self.handle, 
            message_bytes, 
            signature.handle
        )
        return result == SAGE_SUCCESS

class Signature:
    def __init__(self, handle):
        self.handle = handle
    
    def __del__(self):
        if hasattr(self, 'handle') and self.handle:
            lib.sage_signature_free(self.handle)
    
    def to_hex(self):
        hex_str = lib.sage_signature_to_hex(self.handle)
        return hex_str.decode('utf-8')

def main():
    print("SAGE Crypto Core Python Example")
    print("=" * 40)
    
    # Initialize the library
    try:
        result = lib.sage_init()
        check_result(result)
        print("✓ Library initialized successfully")
    except SageError as e:
        print(f"✗ Failed to initialize library: {e}")
        return 1
    
    # Test Ed25519
    print("\nTesting Ed25519:")
    try:
        keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
        message = "Hello, SAGE Crypto Core!"
        
        # Sign the message
        signature = keypair.sign_string(message)
        print(f"✓ Message signed successfully")
        print(f"  Message: {message}")
        print(f"  Signature: {signature.to_hex()}")
        
        # Verify the signature
        is_valid = keypair.verify_string(message, signature)
        print(f"✓ Signature verification: {'VALID' if is_valid else 'INVALID'}")
        
        # Test with wrong message
        wrong_message = "Wrong message"
        is_valid_wrong = keypair.verify_string(wrong_message, signature)
        print(f"✓ Wrong message verification: {'VALID' if is_valid_wrong else 'INVALID'}")
        
    except SageError as e:
        print(f"✗ Ed25519 test failed: {e}")
        return 1
    
    # Test Secp256k1
    print("\nTesting Secp256k1:")
    try:
        keypair_secp = KeyPair(SAGE_KEY_TYPE_SECP256K1)
        message = "Hello, Secp256k1!"
        
        # Sign the message
        signature_secp = keypair_secp.sign_string(message)
        print(f"✓ Message signed successfully")
        print(f"  Message: {message}")
        print(f"  Signature: {signature_secp.to_hex()}")
        
        # Verify the signature
        is_valid_secp = keypair_secp.verify_string(message, signature_secp)
        print(f"✓ Signature verification: {'VALID' if is_valid_secp else 'INVALID'}")
        
    except SageError as e:
        print(f"✗ Secp256k1 test failed: {e}")
        return 1
    
    # Performance test
    print("\nPerformance Test:")
    try:
        import time
        
        keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
        message = "Performance test message"
        
        # Sign performance
        start_time = time.time()
        signatures = []
        for i in range(100):
            sig = keypair.sign_string(f"{message} {i}")
            signatures.append(sig)
        sign_time = time.time() - start_time
        
        # Verify performance
        start_time = time.time()
        for i, sig in enumerate(signatures):
            is_valid = keypair.verify_string(f"{message} {i}", sig)
            assert is_valid, f"Signature {i} verification failed"
        verify_time = time.time() - start_time
        
        print(f"✓ 100 signatures generated in {sign_time:.3f}s ({100/sign_time:.1f} ops/sec)")
        print(f"✓ 100 signatures verified in {verify_time:.3f}s ({100/verify_time:.1f} ops/sec)")
        
    except Exception as e:
        print(f"✗ Performance test failed: {e}")
        return 1
    
    print("\n✓ All tests passed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())