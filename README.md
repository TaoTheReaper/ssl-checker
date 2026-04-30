# ssl-checker

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![No Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20only-green?style=for-the-badge)

## Overview

SSL/TLS certificate and cipher suite analyzer. Checks certificate validity, expiry, SANs, cipher strength, and whether weak protocols (TLSv1.0, TLSv1.1) are accepted.

## Why this project

SSL/TLS misconfigurations are among the most common findings in security assessments. This tool demonstrates network programming, certificate parsing, and security-aware analysis — and requires zero external dependencies.

## Features

- Certificate: subject, issuer, expiry date, days remaining, SANs
- Cipher: name, protocol version, key length, weak cipher detection
- Weak protocol check: tests if TLSv1.0 and TLSv1.1 are accepted
- Findings: CRITICAL / HIGH / MEDIUM / INFO severity
- JSON report output

## Setup

```bash
git clone https://github.com/TaoTheReaper/ssl-checker
cd ssl-checker
# No dependencies needed — stdlib only
```

## Usage

```bash
python3 ssl-checker.py example.com
python3 ssl-checker.py example.com --port 8443
python3 ssl-checker.py example.com -o report.json
python3 ssl-checker.py --help
```

## Lessons Learned

- TLSv1.0/1.1 are officially deprecated (RFC 8996) but still widely accepted
- Cipher suite weakness depends on key exchange, bulk encryption, AND MAC — all three matter
- Certificate expiry monitoring should be automated — 30-day warning is industry standard
