# Security Policy

## Reporting Vulnerabilities

The NTI team takes security issues seriously. If you discover a vulnerability or security issue in `nti-scanner`, please report it privately.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Email security reports to: **abisheakp197@gmail.com**

Include:
- Summary of the vulnerability
- Reproduction steps or proof of concept
- Potential impact

We will respond promptly and coordinate a fix release.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

`nti-scanner` is a static analysis security tool (SAST). It analyzes untrusted Python codebases safely via AST parsing without executing target code. File size limits (10MB) and binary file checks prevent memory blowup and parser exhaustion.
