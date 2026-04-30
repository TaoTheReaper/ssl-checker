#!/usr/bin/env python3
"""ssl-checker — SSL/TLS certificate and cipher suite analyzer."""

import argparse
import json
import logging
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("ssl-checker")

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "RC2", "IDEA"
}

def setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def get_cert(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()
                return {"cert": cert, "cipher": cipher, "protocol": proto, "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"cert": None, "cipher": None, "protocol": None, "error": f"cert verification failed: {e}"}
    except ssl.SSLError as e:
        return {"cert": None, "cipher": None, "protocol": None, "error": f"SSL error: {e}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"cert": None, "cipher": None, "protocol": None, "error": f"connection failed: {e}"}

def parse_cert(cert: dict) -> dict:
    if not cert:
        return {}

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))

    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now        = datetime.now(timezone.utc)
    days_left  = (not_after - now).days

    sans = []
    for typ, val in cert.get("subjectAltName", []):
        if typ == "DNS":
            sans.append(val)

    return {
        "subject_cn":   subject.get("commonName"),
        "issuer_cn":    issuer.get("commonName"),
        "issuer_org":   issuer.get("organizationName"),
        "not_before":   not_before.isoformat(),
        "not_after":    not_after.isoformat(),
        "days_left":    days_left,
        "expired":      days_left < 0,
        "expires_soon": 0 <= days_left <= 30,
        "sans":         sans,
    }

def analyze_cipher(cipher_tuple) -> dict:
    if not cipher_tuple:
        return {}
    name, proto, bits = cipher_tuple
    is_weak = any(w in name.upper() for w in WEAK_CIPHERS)
    return {
        "name":     name,
        "protocol": proto,
        "bits":     bits,
        "is_weak":  is_weak,
    }

def check_weak_protocols(host: str, port: int) -> list[str]:
    """Try to connect with older protocols to check if they're accepted."""
    found = []
    for proto_const, proto_name in [
        (ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
        (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
    ]:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    found.append("TLSv1.0")
        except Exception:
            pass
        try:
            ctx2 = ssl.SSLContext(proto_const)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx2.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host):
                    found.append("TLSv1.1")
        except Exception:
            pass
        break
    return found

def build_findings(parsed: dict, cipher: dict, weak_protos: list) -> list[dict]:
    findings = []

    if parsed.get("expired"):
        findings.append({"severity": "CRITICAL", "issue": "Certificate is EXPIRED"})
    elif parsed.get("expires_soon"):
        findings.append({"severity": "HIGH", "issue": f"Certificate expires in {parsed['days_left']} days"})
    else:
        findings.append({"severity": "INFO", "issue": f"Certificate valid for {parsed.get('days_left')} days"})

    if cipher.get("is_weak"):
        findings.append({"severity": "HIGH", "issue": f"Weak cipher in use: {cipher.get('name')}"})

    if cipher.get("bits", 256) < 128:
        findings.append({"severity": "CRITICAL", "issue": f"Very short key length: {cipher.get('bits')} bits"})

    for p in weak_protos:
        findings.append({"severity": "HIGH", "issue": f"Weak protocol accepted: {p}"})

    proto = cipher.get("protocol", "")
    if proto in ("TLSv1", "TLSv1.1"):
        findings.append({"severity": "HIGH", "issue": f"Negotiated with weak protocol: {proto}"})
    elif proto in ("TLSv1.2", "TLSv1.3"):
        findings.append({"severity": "INFO", "issue": f"Protocol OK: {proto}"})

    return findings

def print_report(host: str, port: int, parsed: dict, cipher: dict, findings: list, conn_error: str | None):
    print(C["cyan"] + f"\n{'='*60}")
    print(f"  SSL CHECKER — {host}:{port}")
    print(f"{'='*60}" + C["reset"])

    if conn_error:
        print(f"\n{C['red']}[!] {conn_error}{C['reset']}")
        return

    print(f"\n{C['green']}Certificate{C['reset']}")
    print(f"  Subject  : {parsed.get('subject_cn')}")
    print(f"  Issuer   : {parsed.get('issuer_cn')} ({parsed.get('issuer_org')})")
    print(f"  Valid to : {parsed.get('not_after')}  ({parsed.get('days_left')} days left)")
    if parsed.get("sans"):
        print(f"  SANs     : {', '.join(parsed['sans'][:5])}")

    print(f"\n{C['green']}Cipher & Protocol{C['reset']}")
    ccolor = C["red"] if cipher.get("is_weak") else C["green"]
    print(f"  Protocol : {cipher.get('protocol')}")
    print(f"  Cipher   : {ccolor}{cipher.get('name')}{C['reset']} ({cipher.get('bits')} bits)")

    print(f"\n{C['green']}Findings{C['reset']}")
    sev_color = {"CRITICAL": C["red"], "HIGH": C["red"], "MEDIUM": C["yellow"], "INFO": C["green"]}
    for f in findings:
        color = sev_color.get(f["severity"], C["reset"])
        print(f"  [{color}{f['severity']}{C['reset']}] {f['issue']}")

    print(C["cyan"] + f"\n{'='*60}" + C["reset"])

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssl-checker",
        description="SSL/TLS certificate and cipher analyzer.",
        epilog="Examples:\n  python ssl-checker.py example.com\n  python ssl-checker.py example.com --port 8443 -o report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("host",              help="Target hostname")
    p.add_argument("-p", "--port",      type=int, default=443, help="Port (default: 443)")
    p.add_argument("-o", "--output",    metavar="FILE", help="Save JSON report")
    p.add_argument("-v", "--verbose",   action="store_true")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    host = args.host.replace("https://", "").replace("http://", "").rstrip("/")
    port = args.port

    print(f"{C['cyan']}[*] Connecting to {host}:{port}...{C['reset']}")
    conn = get_cert(host, port)

    parsed  = parse_cert(conn["cert"])
    cipher  = analyze_cipher(conn["cipher"])
    weak_p  = check_weak_protocols(host, port) if not conn["error"] else []
    findings = build_findings(parsed, cipher, weak_p) if not conn["error"] else []

    print_report(host, port, parsed, cipher, findings, conn["error"])

    if args.output and not conn["error"]:
        report = {
            "host": host, "port": port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificate": parsed,
            "cipher": cipher,
            "weak_protocols": weak_p,
            "findings": findings,
        }
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, args.output)
        print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")

if __name__ == "__main__":
    main()
