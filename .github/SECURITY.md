# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The SAGE Crypto Core team takes security seriously. If you discover a security vulnerability, please report it privately to allow us to fix it before public disclosure.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to: security@sage-project.io
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 24 hours
- **Investigation**: We will investigate the issue and may ask for additional information
- **Resolution**: We will work to fix the vulnerability as quickly as possible
- **Disclosure**: We will coordinate with you on public disclosure timing

### Security Measures

This project implements several security measures:

- **Memory Safety**: Rust's ownership system prevents many common vulnerabilities
- **Cryptographic Security**: Uses well-vetted cryptographic libraries
- **Input Validation**: All inputs are validated before processing
- **Secure Defaults**: Safe defaults are used throughout the API
- **Regular Audits**: Dependencies are regularly audited for vulnerabilities

### Scope

This security policy covers:
- The core Rust library
- FFI bindings
- WASM bindings
- Build and release processes

### Out of Scope

The following are generally out of scope:
- Vulnerabilities in example code (unless they demonstrate unsafe library usage)
- Issues in third-party dependencies (please report to upstream)
- Theoretical attacks without practical impact

### Responsible Disclosure

We appreciate security researchers who:
- Follow responsible disclosure practices
- Provide clear and actionable reports
- Allow reasonable time for fixes before public disclosure
- Avoid accessing, modifying, or deleting data during testing

### Recognition

We maintain a security hall of fame to recognize researchers who help improve our security. With your permission, we will acknowledge your contribution in our security announcements.

## Security Best Practices for Users

When using SAGE Crypto Core:

1. **Keep Updated**: Always use the latest version
2. **Secure Storage**: Properly secure private keys
3. **Validate Inputs**: Always validate external inputs
4. **Use HTTPS**: Protect data in transit
5. **Monitor Dependencies**: Keep dependencies updated
6. **Follow Examples**: Use our examples as security guidance

## Security Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 9421 - HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)

For questions about security practices, please contact security@sage-project.io.