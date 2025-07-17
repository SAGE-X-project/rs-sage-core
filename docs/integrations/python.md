# Python Integration Guide

This guide shows how to use SAGE Crypto Core from Python using ctypes to interface with the C FFI.

## Installation

First, ensure you have the SAGE Crypto Core library installed:

```bash
# On Ubuntu/Debian
sudo apt install libsage-crypto-core-dev

# On macOS with Homebrew
brew install sage-crypto-core

# On Windows
# Download and install the MSI from releases
```

## Basic Usage

### Python Wrapper

Create a Python wrapper for the C library:

```python
import ctypes
from ctypes import Structure, POINTER, c_char_p, c_int, c_void_p, c_size_t
import platform

# Load the library
if platform.system() == "Windows":
    lib = ctypes.CDLL("sage_crypto_core.dll")
elif platform.system() == "Darwin":
    lib = ctypes.CDLL("libsage_crypto_core.dylib")
else:
    lib = ctypes.CDLL("libsage_crypto_core.so")

# Define constants
SAGE_SUCCESS = 0
SAGE_KEY_TYPE_ED25519 = 0
SAGE_KEY_TYPE_SECP256K1 = 1

# Define opaque handle types
class SageKeyPair(Structure):
    pass

class SageSignature(Structure):
    pass

class SageHttpSigner(Structure):
    pass

# Define function signatures
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

class SageError(Exception):
    pass

def check_result(result):
    if result != SAGE_SUCCESS:
        error_msg = lib.sage_get_last_error()
        raise SageError(error_msg.decode('utf-8') if error_msg else "Unknown error")
```

### KeyPair Class

```python
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
```

### Usage Example

```python
# Initialize the library
result = lib.sage_init()
check_result(result)

# Generate a key pair
keypair = KeyPair(SAGE_KEY_TYPE_ED25519)

# Sign a message
message = "Hello, SAGE!"
signature = keypair.sign_string(message)

print(f"Message: {message}")
print(f"Signature: {signature.to_hex()}")

# Verify the signature
is_valid = keypair.verify_string(message, signature)
print(f"Signature valid: {is_valid}")
```

## HTTP Signatures

### Extended HTTP Signer

```python
class HttpRequest(Structure):
    _fields_ = [
        ("method", c_char_p),
        ("url", c_char_p),
        ("headers", c_void_p),
        ("body", c_char_p),
        ("body_length", c_size_t)
    ]

class HttpSigner:
    def __init__(self, keypair):
        self.keypair = keypair
        self.handle = POINTER(SageHttpSigner)()
        result = lib.sage_http_signer_new(keypair.handle, ctypes.byref(self.handle))
        check_result(result)
    
    def __del__(self):
        if hasattr(self, 'handle') and self.handle:
            lib.sage_http_signer_free(self.handle)
    
    def sign_request(self, method, url, headers=None, body=None):
        # Convert headers dict to C format
        # Implementation depends on your C API header format
        request = HttpRequest()
        request.method = method.encode('utf-8')
        request.url = url.encode('utf-8')
        
        if body:
            request.body = body.encode('utf-8')
            request.body_length = len(body)
        
        # Call C function to sign request
        signature_handle = POINTER(SageSignature)()
        result = lib.sage_http_signer_sign_request(
            self.handle,
            ctypes.byref(request),
            ctypes.byref(signature_handle)
        )
        check_result(result)
        
        return Signature(signature_handle)

# Usage
signer = HttpSigner(keypair)
http_signature = signer.sign_request("POST", "https://api.example.com/data")
print(f"HTTP Signature: {http_signature.to_hex()}")
```

## Advanced Usage

### Context Manager

```python
class SageContext:
    def __init__(self):
        result = lib.sage_init()
        check_result(result)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup if needed
        pass

# Usage with context manager
with SageContext():
    keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
    signature = keypair.sign_string("Hello, World!")
    print(f"Signature: {signature.to_hex()}")
```

### Async Support

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

class AsyncKeyPair:
    def __init__(self, key_type=SAGE_KEY_TYPE_ED25519):
        self.keypair = KeyPair(key_type)
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def sign_string_async(self, message):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor, 
            self.keypair.sign_string, 
            message
        )
    
    async def verify_string_async(self, message, signature):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self.keypair.verify_string,
            message,
            signature
        )

# Async usage
async def main():
    keypair = AsyncKeyPair()
    signature = await keypair.sign_string_async("Hello, Async!")
    is_valid = await keypair.verify_string_async("Hello, Async!", signature)
    print(f"Async signature valid: {is_valid}")

asyncio.run(main())
```

## Performance Optimization

### Batch Operations

```python
class BatchSigner:
    def __init__(self, keypair):
        self.keypair = keypair
    
    def sign_batch(self, messages):
        signatures = []
        for message in messages:
            signature = self.keypair.sign_string(message)
            signatures.append(signature)
        return signatures
    
    def verify_batch(self, message_signature_pairs):
        results = []
        for message, signature in message_signature_pairs:
            is_valid = self.keypair.verify_string(message, signature)
            results.append(is_valid)
        return results

# Usage
batch_signer = BatchSigner(keypair)
messages = ["msg1", "msg2", "msg3"]
signatures = batch_signer.sign_batch(messages)
pairs = list(zip(messages, signatures))
results = batch_signer.verify_batch(pairs)
```

## Error Handling

### Custom Exception Classes

```python
class SageInitError(SageError):
    pass

class SageKeyError(SageError):
    pass

class SageSignatureError(SageError):
    pass

def safe_init():
    try:
        result = lib.sage_init()
        check_result(result)
    except SageError as e:
        raise SageInitError(f"Failed to initialize SAGE: {e}")

def safe_generate_keypair(key_type):
    try:
        return KeyPair(key_type)
    except SageError as e:
        raise SageKeyError(f"Failed to generate keypair: {e}")
```

## Testing

### Unit Tests

```python
import unittest

class TestSageCrypto(unittest.TestCase):
    def setUp(self):
        result = lib.sage_init()
        check_result(result)
    
    def test_keypair_generation(self):
        keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
        self.assertIsNotNone(keypair.handle)
    
    def test_sign_verify(self):
        keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
        message = "test message"
        signature = keypair.sign_string(message)
        self.assertTrue(keypair.verify_string(message, signature))
    
    def test_invalid_signature(self):
        keypair = KeyPair(SAGE_KEY_TYPE_ED25519)
        message = "test message"
        signature = keypair.sign_string(message)
        self.assertFalse(keypair.verify_string("different message", signature))

if __name__ == '__main__':
    unittest.main()
```

## Installation Script

```python
#!/usr/bin/env python3
"""
Installation script for SAGE Crypto Core Python bindings
"""

import subprocess
import sys
import platform

def install_sage_crypto():
    system = platform.system()
    
    if system == "Linux":
        # Ubuntu/Debian
        subprocess.run([
            "sudo", "apt", "update", "&&", 
            "sudo", "apt", "install", "libsage-crypto-core-dev"
        ], shell=True)
    elif system == "Darwin":
        # macOS
        subprocess.run([
            "brew", "install", "sage-crypto-core"
        ])
    elif system == "Windows":
        print("Please download and install the MSI from:")
        print("https://github.com/sage-x-project/rs-sage-core/releases")
        return False
    
    return True

if __name__ == "__main__":
    if install_sage_crypto():
        print("SAGE Crypto Core installed successfully!")
    else:
        print("Installation failed!")
        sys.exit(1)
```

## Package Distribution

### setup.py

```python
from setuptools import setup, find_packages

setup(
    name="sage-crypto-core",
    version="0.1.0",
    description="Python bindings for SAGE Crypto Core",
    author="SAGE Project",
    author_email="contact@sage-project.io",
    url="https://github.com/sage-x-project/rs-sage-core",
    packages=find_packages(),
    install_requires=[
        # No Python dependencies for FFI bindings
    ],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
)
```

This guide provides comprehensive Python integration for SAGE Crypto Core, including basic usage, async support, performance optimization, and proper error handling.