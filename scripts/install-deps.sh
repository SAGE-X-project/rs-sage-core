#!/bin/bash

# Install dependencies for cross-compilation
# Usage: ./scripts/install-deps.sh

set -e

echo "Installing cross-compilation dependencies..."

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    "Linux")
        echo "Detected Linux"
        # Install cross-compilation toolchains
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian
            sudo apt-get update
            sudo apt-get install -y \
                gcc-multilib \
                gcc-aarch64-linux-gnu \
                gcc-x86-64-linux-gnu \
                musl-tools \
                gcc-mingw-w64 \
                pkg-config \
                libssl-dev
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            sudo yum install -y \
                gcc \
                gcc-c++ \
                openssl-devel \
                pkg-config
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            sudo pacman -S --needed \
                gcc \
                mingw-w64-gcc \
                pkg-config \
                openssl
        fi
        ;;
    "Darwin")
        echo "Detected macOS"
        # Install Xcode command line tools if not present
        if ! command -v clang &> /dev/null; then
            echo "Installing Xcode command line tools..."
            xcode-select --install
        fi
        
        # Install Homebrew dependencies
        if command -v brew &> /dev/null; then
            brew install pkg-config openssl
        else
            echo "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
        ;;
    *)
        echo "Unsupported OS: ${OS}"
        exit 1
        ;;
esac

# Install Rust targets
echo "Installing Rust targets..."
rustup target add \
    x86_64-unknown-linux-gnu \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-gnu \
    x86_64-apple-darwin \
    aarch64-apple-darwin \
    x86_64-pc-windows-gnu \
    wasm32-unknown-unknown

# Install wasm-pack for WASM builds
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Install cargo-cross for easier cross-compilation
if ! command -v cross &> /dev/null; then
    echo "Installing cargo-cross..."
    cargo install cross
fi

echo "✓ Dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run: ./scripts/build-all.sh"
echo "  2. Test: cd examples/ffi && make"
echo "  3. Test WASM: cd examples/wasm && npm start"