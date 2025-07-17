class SageCryptoCore < Formula
  desc "Core cryptographic library for SAGE with RFC 9421 support"
  homepage "https://github.com/sage-x-project/rs-sage-core"
  url "https://github.com/sage-x-project/rs-sage-core/archive/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"  # Will be updated during release
  license "MIT OR Apache-2.0"
  head "https://github.com/sage-x-project/rs-sage-core.git", branch: "main"

  depends_on "rust" => :build
  depends_on "pkg-config" => :build
  depends_on "openssl@3"

  def install
    system "cargo", "build", "--release", "--features", "ffi"
    
    # Install library
    lib.install "target/release/libsage_crypto_core.dylib"
    lib.install "target/release/libsage_crypto_core.a"
    
    # Install header
    include.install "include/sage_crypto.h"
    
    # Install documentation
    doc.install "README.md"
    doc.install "CHANGELOG.md" if File.exist?("CHANGELOG.md")
  end

  test do
    # Test basic functionality
    (testpath/"test.c").write <<~EOS
      #include <sage_crypto.h>
      #include <stdio.h>
      
      int main() {
          if (sage_init() != SAGE_SUCCESS) {
              printf("Failed to initialize SAGE library\\n");
              return 1;
          }
          
          printf("SAGE Crypto Core version: %s\\n", sage_version());
          
          // Test key generation
          SageKeyPair* keypair = NULL;
          if (sage_keypair_generate(SAGE_KEY_TYPE_ED25519, &keypair) != SAGE_SUCCESS) {
              printf("Failed to generate key pair\\n");
              return 1;
          }
          
          sage_keypair_free(keypair);
          printf("Basic functionality test passed\\n");
          return 0;
      }
    EOS
    
    system ENV.cc, "test.c", "-L#{lib}", "-lsage_crypto_core", "-o", "test"
    system "./test"
  end
end