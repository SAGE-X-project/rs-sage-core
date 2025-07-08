.PHONY: all build test bench clean docs release

# Default target
all: build test

# Build the library
build:
	cargo build --all-features

# Build release version
release:
	cargo build --release --all-features

# Run tests
test:
	cargo test --all-features

# Run benchmarks
bench:
	cargo bench

# Generate documentation
docs:
	cargo doc --all-features --no-deps --open

# Build for FFI
ffi: release
	@echo "FFI library built at target/release/"
	@ls -la target/release/libsage_crypto_core.*

# Build WASM
wasm:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Installing wasm-pack..."; cargo install wasm-pack; }
	wasm-pack build --target web --out-dir pkg

# Clean build artifacts
clean:
	cargo clean
	rm -rf pkg/

# Format code
fmt:
	cargo fmt

# Lint code
lint:
	cargo clippy --all-features -- -D warnings

# Check code
check: fmt lint test

# Install development dependencies
dev-setup:
	rustup component add rustfmt clippy
	cargo install cargo-tarpaulin
	cargo install wasm-pack

# Run code coverage
coverage:
	cargo tarpaulin --out Html --output-dir coverage

# Example commands
example-basic:
	cargo run --example basic_signing

example-http:
	cargo run --example http_signatures
