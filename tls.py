#!/usr/bin/env python3
"""
TLS -Transport Layer Security/ Certificate Checker
-------------------------
Audits the TLS configuration of a host: certificate validity and expiry,
hostname match, chain trust, supported protocol versions, negotiated cipher,
and HTTPS-related red flags. Produces a score and letter grade.

ONLY scan hosts you own or have written permission to test.

Usage:
    python tls_checker.py example.com
    python tls_checker.py example.com --port 8443 --json report.json
    python tls_checker.py host1.com host2.com host3.com --yes

Optional (adds key size / signature algorithm checks):
    pip install cryptography
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

WEAK_CIPHER_MARKERS = ["RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon"]

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1, True),    # (name, version, insecure?)
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, False),
]


class Finding:
    def __init__(self, category, name, status, points, max_points, detail, fix=""):
        self.category, self.name, self.status = category, name, status
        self.points, self.max_points = points, max_points
        self.detail, self.fix = detail, fix

    def to_dict(self):
        return self.__dict__


# ---------- Connection helpers ----------
def fetch_cert(host, port, timeout, verify):
    """Return (cert_dict, der_bytes, protocol, cipher, error)."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                cert = s.getpeercert() if verify else {}
                return cert, der, s.version(), s.cipher(), None
    except ssl.SSLCertVerificationError as e:
        return None, None, None, None, ("verify", e.verify_message)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        return None, None, None, None, ("conn", str(e))


def supports_protocol(host, port, timeout, version):
    """Try to connect forcing exactly one TLS version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        # Old protocols are often disabled in the local OpenSSL build
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None  # cannot test locally
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, ConnectionError, socket.timeout, OSError):
        return False


# ---------- Checks ----------
def check_trust(host, port, timeout):
    findings = []
    cert, der, proto, cipher, err = fetch_cert(host, port, timeout, verify=True)
    if err and err[0] == "verify":
        findings.append(Finding("Certificate", "Trust and hostname", "FAIL", 0, 25,
                                f"Verification failed: {err[1]}",
                                "Install a certificate from a trusted CA that matches the hostname, "
                                "with the full intermediate chain."))
        # fall back to unverified fetch so we can still inspect it
        cert, der, proto, cipher, err2 = fetch_cert(host, port, timeout, verify=False)
        if err2:
            return findings, None, None, None, None
        return findings, None, der, proto, cipher
    if err:
        findings.append(Finding("Connection", "TLS handshake", "FAIL", 0, 25,
                                f"Could not complete handshake: {err[1]}",
                                "Check host, port, and that TLS is enabled."))
        return findings, None, None, None, None
    findings.append(Finding("Certificate", "Trust and hostname", "PASS", 25, 25,
                            "Chain is trusted and hostname matches."))
    return findings, cert, der, proto, cipher


def check_expiry(cert, der):
    not_after = None
    if cert and cert.get("notAfter"):
        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),
                                           tz=timezone.utc)
    elif HAVE_CRYPTO and der:
        c = x509.load_der_x509_certificate(der)
        not_after = c.not_valid_after_utc if hasattr(c, "not_valid_after_utc") \
            else c.not_valid_after.replace(tzinfo=timezone.utc)
    if not not_after:
        return [Finding("Certificate", "Expiry", "WARN", 0, 15,
                        "Could not determine expiry date.")]
    days = (not_after - datetime.now(timezone.utc)).days
    when = not_after.strftime("%Y-%m-%d")
    if days < 0:
        return [Finding("Certificate", "Expiry", "FAIL", 0, 15,
                        f"EXPIRED {-days} days ago ({when}).", "Renew the certificate immediately.")]
    if days < 14:
        return [Finding("Certificate", "Expiry", "FAIL", 5, 15,
                        f"Expires in {days} days ({when}).", "Renew now; automate with ACME/certbot.")]
    if days < 30:
        return [Finding("Certificate", "Expiry", "WARN", 10, 15,
                        f"Expires in {days} days ({when}).", "Schedule renewal; automate if possible.")]
    return [Finding("Certificate", "Expiry", "PASS", 15, 15, f"Valid for {days} more days ({when}).")]


def check_cert_strength(der):
    if not HAVE_CRYPTO or not der:
        return [Finding("Certificate", "Key and signature strength", "WARN", 5, 10,
                        "Skipped (install 'cryptography' for key size and signature checks).")]
    c = x509.load_der_x509_certificate(der)
    pub = c.public_key()
    problems, desc = [], ""
    if isinstance(pub, rsa.RSAPublicKey):
        desc = f"RSA {pub.key_size}-bit"
        if pub.key_size < 2048:
            problems.append("RSA key under 2048 bits")
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        desc = f"EC {pub.curve.name}"
        if pub.key_size < 256:
            problems.append("EC key under 256 bits")
    else:
        desc = type(pub).__name__
    sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "unknown"
    desc += f", signed with {sig}"
    if sig in ("md5", "sha1"):
        problems.append(f"weak signature hash ({sig})")
    if problems:
        return [Finding("Certificate", "Key and signature strength", "FAIL", 0, 10,
                        f"{desc}: {', '.join(problems)}.",
                        "Reissue with RSA 2048+ (or ECDSA P-256) and SHA-256 or better.")]
    return [Finding("Certificate", "Key and signature strength", "PASS", 10, 10, desc + ".")]


def check_protocols(host, port, timeout):
    findings = []
    results = {}
    for name, ver, insecure in PROTOCOLS:
        results[name] = supports_protocol(host, port, timeout, ver)

    for name, ver, insecure in PROTOCOLS:
        r = results[name]
        if insecure:
            if r is True:
                findings.append(Finding("Protocols", name, "FAIL", 0, 10,
                                        "Deprecated protocol is ENABLED.",
                                        f"Disable {name} on the server; require TLS 1.2+."))
            elif r is False:
                findings.append(Finding("Protocols", name, "PASS", 10, 10, "Disabled (good)."))
            else:
                findings.append(Finding("Protocols", name, "WARN", 5, 10,
                                        "Could not test (local OpenSSL refuses legacy protocol)."))
        elif name == "TLSv1.2":
            if r is True:
                findings.append(Finding("Protocols", name, "PASS", 5, 5, "Supported."))
            else:
                findings.append(Finding("Protocols", name, "WARN", 2, 5,
                                        "Not supported; some clients may fail to connect."))
        else:  # TLS 1.3
            if r is True:
                findings.append(Finding("Protocols", name, "PASS", 10, 10, "Supported (modern)."))
            else:
                findings.append(Finding("Protocols", name, "WARN", 0, 10,
                                        "Not supported.", "Enable TLS 1.3 for better security and speed."))
    return findings


def check_cipher(proto, cipher):
    if not cipher:
        return []
    name, _, bits = cipher
    weak = [m for m in WEAK_CIPHER_MARKERS if m.lower() in name.lower()]
    forward_secret = proto == "TLSv1.3" or "ECDHE" in name or "DHE" in name
    if weak or (bits and bits < 128):
        return [Finding("Cipher", "Negotiated cipher", "FAIL", 0, 10,
                        f"{name} ({bits}-bit) is weak: {', '.join(weak) or 'low strength'}.",
                        "Restrict to AEAD suites (AES-GCM / ChaCha20-Poly1305).")]
    if not forward_secret:
        return [Finding("Cipher", "Negotiated cipher", "WARN", 5, 10,
                        f"{name} lacks forward secrecy.",
                        "Prefer ECDHE key exchange suites.")]
    return [Finding("Cipher", "Negotiated cipher", "PASS", 10, 10,
                    f"{name} ({bits}-bit) with forward secrecy.")]


# ---------- Output ----------
def grade(pct):
    for t, l in [(95, "A+"), (85, "A"), (75, "B"), (60, "C"), (45, "D")]:
        if pct >= t:
            return l
    return "F"


def print_report(host, port, findings, score, mx, letter, proto):
    tty = sys.stdout.isatty()
    col = {"PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m"} if tty else {}
    end = "\033[0m" if tty else ""
    print(f"\nTLS Report for {host}:{port}   (negotiated: {proto or 'n/a'})")
    print(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    cur = None
    for f in findings:
        if f.category != cur:
            cur = f.category
            print(f"\n[{cur}]")
        print(f"  {col.get(f.status, '')}{f.status:<4}{end} {f.name} ({f.points}/{f.max_points})")
        print(f"       {f.detail}")
        if f.fix and f.status != "PASS":
            print(f"       Fix: {f.fix}")
    print("\n" + "=" * 70)
    print(f"SCORE: {score}/{mx} ({round(score / mx * 100)}%)   GRADE: {letter}\n")


def scan(host, port, timeout):
    findings, cert, der, proto, cipher = check_trust(host, port, timeout)
    if der is None and not any(f.category == "Certificate" for f in findings):
        pass  # handshake failed entirely
    if der is not None:
        findings += check_expiry(cert, der)
        findings += check_cert_strength(der)
        findings += check_protocols(host, port, timeout)
        findings += check_cipher(proto, cipher)
    score = sum(f.points for f in findings)
    mx = max(sum(f.max_points for f in findings), 1)
    return findings, score, mx, grade(score / mx * 100), proto


def main():
    p = argparse.ArgumentParser(description="TLS / certificate checker")
    p.add_argument("hosts", nargs="+", help="Hostname(s) to scan (no scheme)")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--json", help="Write JSON report to this path")
    p.add_argument("--yes", action="store_true", help="Confirm you are authorized to test these hosts")
    args = p.parse_args()

    if not args.yes:
        ans = input(f"Do you own or have written permission to test {', '.join(args.hosts)}? [y/N] ")
        if ans.strip().lower() != "y":
            print("Aborted. Only scan hosts you are authorized to test.")
            sys.exit(1)

    all_results = []
    for raw in args.hosts:
        host = raw.replace("https://", "").replace("http://", "").split("/")[0]
        findings, score, mx, letter, proto = scan(host, args.port, args.timeout)
        print_report(host, args.port, findings, score, mx, letter, proto)
        all_results.append({"host": host, "port": args.port, "score": score, "max": mx,
                            "grade": letter, "findings": [f.to_dict() for f in findings]})

    if len(all_results) > 1:
        print("SUMMARY")
        for r in all_results:
            print(f"  {r['host']:<35} {r['grade']:<3} {r['score']}/{r['max']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(all_results, fh, indent=2)
        print(f"\nJSON saved to {args.json}")


if __name__ == "__main__":
    main()
