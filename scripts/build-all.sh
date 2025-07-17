#!/bin/bash

# Build script for all supported platforms
# Usage: ./scripts/build-all.sh [release|debug]

set -e

BUILD_TYPE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Building SAGE Crypto Core for all platforms..."
echo "Build type: ${BUILD_TYPE}"
echo "Project directory: ${PROJECT_DIR}"

cd "${PROJECT_DIR}"

# Define targets
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-gnu"
    "wasm32-unknown-unknown"
)

# Build flags
if [ "$BUILD_TYPE" = "release" ]; then
    BUILD_FLAGS="--release"
else
    BUILD_FLAGS=""
fi

# Create output directory
OUTPUT_DIR="${PROJECT_DIR}/dist"
mkdir -p "${OUTPUT_DIR}"

# Function to build for a target
build_target() {
    local target=$1
    echo "Building for target: ${target}"
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "${target}"; then
        echo "Installing target: ${target}"
        rustup target add "${target}"
    fi
    
    # Build with appropriate features
    case "${target}" in
        "wasm32-unknown-unknown")
            cargo build --target "${target}" --features wasm ${BUILD_FLAGS}
            ;;
        *)
            cargo build --target "${target}" --features ffi ${BUILD_FLAGS}
            ;;
    esac
    
    # Copy outputs
    local target_dir="target/${target}/${BUILD_TYPE}"
    local output_target_dir="${OUTPUT_DIR}/${target}"
    mkdir -p "${output_target_dir}"
    
    # Copy library files
    case "${target}" in
        *"windows"*)
            cp "${target_dir}/sage_crypto_core.dll" "${output_target_dir}/" 2>/dev/null || true
            cp "${target_dir}/sage_crypto_core.lib" "${output_target_dir}/" 2>/dev/null || true
            cp "${target_dir}/sage_crypto_core.dll.lib" "${output_target_dir}/" 2>/dev/null || true
            ;;
        *"apple"*)
            cp "${target_dir}/libsage_crypto_core.dylib" "${output_target_dir}/" 2>/dev/null || true
            cp "${target_dir}/libsage_crypto_core.a" "${output_target_dir}/" 2>/dev/null || true
            ;;
        "wasm32-unknown-unknown")
            cp "${target_dir}/sage_crypto_core.wasm" "${output_target_dir}/" 2>/dev/null || true
            ;;
        *)
            cp "${target_dir}/libsage_crypto_core.so" "${output_target_dir}/" 2>/dev/null || true
            cp "${target_dir}/libsage_crypto_core.a" "${output_target_dir}/" 2>/dev/null || true
            ;;
    esac
    
    # Copy header files for non-WASM targets
    if [[ "${target}" != "wasm32-unknown-unknown" ]]; then
        cp include/sage_crypto.h "${output_target_dir}/" 2>/dev/null || true
    fi
    
    echo "✓ Built for ${target}"
}

# Build for all targets
for target in "${TARGETS[@]}"; do
    # Skip targets that require special toolchains if not available
    case "${target}" in
        "x86_64-unknown-linux-gnu"|"x86_64-unknown-linux-musl"|"aarch64-unknown-linux-gnu")
            if [[ "$OSTYPE" != "linux-gnu"* ]]; then
                echo "Skipping ${target} (requires Linux host or cross-compilation toolchain)"
                continue
            fi
            ;;
        "x86_64-pc-windows-gnu")
            if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
                echo "Skipping ${target} (requires mingw-w64 toolchain)"
                continue
            fi
            ;;
        "x86_64-apple-darwin")
            if [[ "$OSTYPE" != "darwin"* ]]; then
                echo "Skipping ${target} (requires macOS host)"
                continue
            fi
            ;;
        "aarch64-apple-darwin")
            if [[ "$OSTYPE" != "darwin"* ]]; then
                echo "Skipping ${target} (requires macOS host)"
                continue
            fi
            ;;
    esac
    
    build_target "${target}"
done

# Build WASM with wasm-pack if available
if command -v wasm-pack &> /dev/null; then
    echo "Building WASM with wasm-pack..."
    wasm-pack build --target web --out-dir pkg --features wasm
    cp -r pkg/* "${OUTPUT_DIR}/wasm32-unknown-unknown/" 2>/dev/null || true
    echo "✓ Built WASM with wasm-pack"
fi

echo ""
echo "Build complete! Output directory: ${OUTPUT_DIR}"
echo "Available targets:"
ls -la "${OUTPUT_DIR}"

echo ""
echo "To test the builds:"
echo "  FFI: cd examples/ffi && make"
echo "  WASM: cd examples/wasm && npm start"