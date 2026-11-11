# TLS -Transport Layer Security/ Certificate Checker

TLS stands for **Transport Layer Security**, the protocol that encrypts
connections between clients and servers.

`tls.py` checks one or more TLS endpoints for certificate trust and hostname
matching, expiry, certificate strength, supported protocol versions, and the
negotiated cipher. It prints findings with a score and letter grade, and can
write results to JSON.

## Requirements

- Python 3.8 or newer
- `cryptography` is optional; when installed, it enables additional
  certificate key-size and signature-algorithm checks

```bash
# Optional dependency:
python -m pip install cryptography
```

## Usage

The script asks you to confirm authorization unless you pass `--yes`:

```bash
python tls.py example.com
python tls.py example.com --port 8443 --json tls-report.json
python tls.py host1.example host2.example --yes
python tls.py example.com --timeout 15
```

Pass hostnames without a URL path. The default port is 443 and the default
connection timeout is 8 seconds.

## Authorization and limitations

Only test hosts you own or have explicit permission to assess. The results
reflect what the checker can negotiate from the current machine and its TLS
library; they are not a full TLS audit or a guarantee of security.
