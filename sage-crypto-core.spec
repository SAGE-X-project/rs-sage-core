Name:           sage-crypto-core
Version:        0.1.0
Release:        1%{?dist}
Summary:        Core cryptographic library for SAGE with RFC 9421 support

License:        MIT OR Apache-2.0
URL:            https://github.com/sage-x-project/rs-sage-core
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  pkg-config
BuildRequires:  openssl-devel

%description
SAGE Crypto Core is a cryptographic library that provides Ed25519 and
Secp256k1 digital signatures with RFC 9421 HTTP Message Signatures support.
The library is designed for high performance and security, with FFI bindings
for C/C++ integration and WebAssembly support for browser environments.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Development files for SAGE Crypto Core library including headers and
static libraries needed to compile applications that use SAGE Crypto Core.

%prep
%autosetup -n rs-sage-core-%{version}

%build
export RUSTFLAGS="-C target-cpu=native"
cargo build --release --features ffi

%install
mkdir -p %{buildroot}%{_libdir}
mkdir -p %{buildroot}%{_includedir}
mkdir -p %{buildroot}%{_docdir}/%{name}

# Install libraries
install -m 755 target/release/libsage_crypto_core.so %{buildroot}%{_libdir}/libsage_crypto_core.so.0.1.0
ln -sf libsage_crypto_core.so.0.1.0 %{buildroot}%{_libdir}/libsage_crypto_core.so.0
ln -sf libsage_crypto_core.so.0 %{buildroot}%{_libdir}/libsage_crypto_core.so

# Install static library
install -m 644 target/release/libsage_crypto_core.a %{buildroot}%{_libdir}/

# Install headers
install -m 644 include/sage_crypto.h %{buildroot}%{_includedir}/

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/
install -m 644 LICENSE-MIT %{buildroot}%{_docdir}/%{name}/
install -m 644 LICENSE-APACHE %{buildroot}%{_docdir}/%{name}/

%check
export RUSTFLAGS="-C target-cpu=native"
cargo test --features ffi --release

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_libdir}/libsage_crypto_core.so.0*

%files devel
%{_includedir}/sage_crypto.h
%{_libdir}/libsage_crypto_core.so
%{_libdir}/libsage_crypto_core.a
%{_docdir}/%{name}/

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%changelog
* Thu Jul 17 2025 SAGE Project <contact@sage-project.io> - 0.1.0-1
- Initial RPM package release
- Ed25519 and Secp256k1 digital signatures support
- RFC 9421 HTTP Message Signatures implementation
- FFI bindings for C/C++ integration
- Multiple key formats support (PEM, DER, JWK)
- Cross-platform compatibility