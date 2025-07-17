# Windows Installer Build Script for SAGE Crypto Core
# Requires: WiX Toolset v3.11 or later

param(
    [string]$Version = "0.1.0",
    [string]$BuildDir = "..\..\target\release",
    [string]$SourceDir = "..\..",
    [string]$OutputDir = ".\output"
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "Building SAGE Crypto Core Windows Installer v$Version" -ForegroundColor Green

# Check if WiX is installed
$wixPath = Get-Command "candle.exe" -ErrorAction SilentlyContinue
if (-not $wixPath) {
    Write-Error "WiX Toolset not found. Please install WiX Toolset v3.11 or later."
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Build the Rust library first
Write-Host "Building Rust library..." -ForegroundColor Yellow
Set-Location $SourceDir
& cargo build --release --features ffi --target x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build Rust library"
    exit 1
}

# Copy DLL to expected location
$dllSource = "target\x86_64-pc-windows-msvc\release\sage_crypto_core.dll"
$dllTarget = "$BuildDir\sage_crypto_core.dll"
if (Test-Path $dllSource) {
    Copy-Item $dllSource $dllTarget -Force
    Write-Host "DLL copied to: $dllTarget" -ForegroundColor Green
} else {
    Write-Error "DLL not found at: $dllSource"
    exit 1
}

# Create import library if needed
$libSource = "target\x86_64-pc-windows-msvc\release\sage_crypto_core.lib"
$libTarget = "$BuildDir\sage_crypto_core.lib"
if (Test-Path $libSource) {
    Copy-Item $libSource $libTarget -Force
    Write-Host "Import library copied to: $libTarget" -ForegroundColor Green
}

# Return to installer directory
Set-Location "installer\windows"

# Compile WiX source
Write-Host "Compiling WiX source..." -ForegroundColor Yellow
& candle.exe -dVersion=$Version -dBuildDir=$BuildDir -dSourceDir=$SourceDir sage-crypto-core.wxs -out "$OutputDir\sage-crypto-core.wixobj"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to compile WiX source"
    exit 1
}

# Link MSI
Write-Host "Linking MSI..." -ForegroundColor Yellow
& light.exe "$OutputDir\sage-crypto-core.wixobj" -out "$OutputDir\sage-crypto-core-$Version.msi"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to link MSI"
    exit 1
}

Write-Host "Windows installer built successfully: $OutputDir\sage-crypto-core-$Version.msi" -ForegroundColor Green

# Optional: Sign the MSI if certificate is available
if ($env:SAGE_CODESIGN_CERT) {
    Write-Host "Signing MSI..." -ForegroundColor Yellow
    & signtool.exe sign /f "$env:SAGE_CODESIGN_CERT" /t http://timestamp.digicert.com "$OutputDir\sage-crypto-core-$Version.msi"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "MSI signed successfully" -ForegroundColor Green
    } else {
        Write-Warning "Failed to sign MSI"
    }
}

Write-Host "Build complete!" -ForegroundColor Green