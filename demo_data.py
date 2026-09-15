"""Sanitized, fully synthetic result set for UI and report demonstrations."""

from __future__ import annotations

import datetime as dt


def build_demo_result() -> dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    assets = [
        {
            "IP": "203.0.113.10", "Hostnames": "portal.example.test", "Original inputs": "example.test",
            "Discovery sources": "Synthetic demo", "Record types": "A", "Ports": [443, 8443],
            "Open TCP ports": "443, 8443", "CVE count": 1, "CPEs": "cpe:2.3:a:example:portal:4.2:*:*:*:*:*:*:*",
            "InternetDB hostnames": "portal.example.test", "Tags": "vpn", "ASN": "AS64500",
            "ASN name": "EXAMPLE-NET", "Country": "TH", "PTR": "portal.example.test",
            "InternetDB status": "Synthetic observation",
        },
        {
            "IP": "198.51.100.25", "Hostnames": "api.example.test", "Original inputs": "example.test",
            "Discovery sources": "Synthetic demo", "Record types": "A", "Ports": [443],
            "Open TCP ports": "443", "CVE count": 0, "CPEs": "", "InternetDB hostnames": "api.example.test",
            "Tags": "cloud", "ASN": "AS64501", "ASN name": "EXAMPLE-CLOUD", "Country": "SG",
            "PTR": "api.example.test", "InternetDB status": "Synthetic observation",
        },
    ]
    cves = [
        {
            "IP": "203.0.113.10", "CVE ID": "CVE-DEMO-0001",
            "Title": "Synthetic remote-access component observation", "CVSS": 9.1,
            "CISA KEV": "Yes", "Known ransomware use": "Unknown", "KEV date added": "Demo only",
            "EPSS": "0.72", "EPSS percentile": "0.96", "Technical Priority": "Urgent",
        }
    ]
    tls_rows = [
        {
            "ip": "203.0.113.10", "port": 443, "hostname": "portal.example.test", "reachable": True,
            "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "subject": "CN=portal.example.test",
            "issuer": "CN=Example Public CA", "san": "portal.example.test", "self_signed": False,
            "not_before": "2026-01-15", "not_after": "2026-10-15", "days_to_expiry": 30,
            "validity_days": 273, "cab_limit_days": 200, "exceeds_cab_limit": True,
            "cab_applicability": "Requires public-trust validation", "public_key_algorithm": "RSA",
            "public_key_size": 2048, "security_strength_bits": 112, "quantum_vulnerable": True,
            "pqc_algorithm": "", "signature_algorithm": "sha256WithRSAEncryption",
            "nist_ir_8547": "Draft: deprecated after 2030; disallowed after 2035",
            "key_exchange_group": "X25519", "key_exchange_pqc": "CLASSICAL-ONLY", "hndl_exposed": True,
            "risk": "Medium",
            "findings": "Expires in 30 days | Classical-only key exchange observed - assess protected-data sensitivity and confidentiality lifetime for HNDL priority",
            "error": "",
        },
        {
            "ip": "198.51.100.25", "port": 443, "hostname": "api.example.test", "reachable": True,
            "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "subject": "CN=api.example.test",
            "issuer": "CN=Example Public CA", "san": "api.example.test", "self_signed": False,
            "not_before": "2026-07-01", "not_after": "2026-12-31", "days_to_expiry": 107,
            "validity_days": 183, "cab_limit_days": 200, "exceeds_cab_limit": False,
            "cab_applicability": "Requires public-trust validation", "public_key_algorithm": "EC secp256r1",
            "public_key_size": 256, "security_strength_bits": 128, "quantum_vulnerable": True,
            "pqc_algorithm": "", "signature_algorithm": "ecdsa-with-SHA256",
            "nist_ir_8547": "Draft: disallowed after 2035", "key_exchange_group": "X25519MLKEM768",
            "key_exchange_pqc": "PQC-PROTECTED", "hndl_exposed": False, "risk": "Low",
            "findings": "Quantum-vulnerable certificate public key; hybrid key exchange observed", "error": "",
        },
    ]
    findings = [
        {
            "Finding ID": "VULN-001", "Priority": "Urgent", "Domain": "Vulnerability",
            "Asset": "203.0.113.10", "Observation": "Synthetic external telemetry associates CVE-DEMO-0001 with the exposed remote-access service.",
            "Evidence": "Synthetic InternetDB association; synthetic KEV and EPSS values", "Confidence": "Demo only",
            "Why it matters": "Known exploitation signals would increase validation and remediation urgency.",
            "Customer validation": "Confirm the product, version, ownership, and whether the observation is applicable.",
            "Suggested next step": "Validate against authenticated inventory and the vendor advisory.",
        },
        {
            "Finding ID": "TLS-001", "Priority": "Medium", "Domain": "TLS / PQC",
            "Asset": "portal.example.test:443", "Observation": "Certificate renewal is approaching and classical-only key exchange was observed.",
            "Evidence": "Synthetic TLS handshake result", "Confidence": "Demo only",
            "Why it matters": "Lifecycle failure can affect availability; long-lived sensitive data may require earlier PQC planning.",
            "Customer validation": "Confirm certificate ownership and the confidentiality lifetime of protected data.",
            "Suggested next step": "Assign renewal ownership and add the endpoint to the cryptographic inventory.",
        },
        {
            "Finding ID": "TLS-002", "Priority": "Review", "Domain": "TLS / PQC",
            "Asset": "api.example.test:443", "Observation": "Hybrid PQC key exchange is available while the certificate remains classical.",
            "Evidence": "Synthetic TLS handshake result", "Confidence": "Demo only",
            "Why it matters": "Certificate and key-exchange migration are separate workstreams.",
            "Customer validation": "Confirm client compatibility and certificate migration dependencies.",
            "Suggested next step": "Retain as a candidate interoperability test endpoint.",
        },
    ]
    return {
        "meta": {
            "customer": "ACME Financial Services (Synthetic)",
            "engagement": "Sanitized external exposure and PQC readiness demonstration",
            "scope": "Synthetic documentation assets only; no real scanning performed",
            "started_at": now, "completed_at": now, "tool_version": "2.0.0-demo",
            "profile": "Sanitized demonstration", "normalized_targets": ["example.test"],
            "method": "Synthetic observations for interface and report demonstration",
        },
        "summary": {
            "public_ips": 2, "open_ports": 3, "cve_associations": 1, "kev_matches": 1,
            "tls_endpoints": 2, "quantum_vulnerable_certs": 2, "classical_only_kex": 1,
            "pqc_protected_kex": 1, "unknown_kex": 0, "urgent_findings": 1, "high_findings": 0,
        },
        "asset_rows": assets,
        "cve_rows": cves,
        "tls_rows": tls_rows,
        "tls_summary": {},
        "findings": findings,
        "source_health": [
            {"Source": "All sources", "Status": "Synthetic demo", "Detail": "No external queries or TLS connections were made"}
        ],
        "rejected_targets": [],
    }
