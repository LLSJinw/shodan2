"""
pqc_tls.py — TLS / certificate assessment with post-quantum classification.

No Streamlit dependency, so the same logic can be reused by a CBOM collector,
a CLI batch job, or the Streamlit app.

Two independent axes are produced for every endpoint, because a certificate
carries two unrelated problems:

    validity  -> operational risk   -> certificate lifecycle management
    algorithm -> obsolescence risk  -> post-quantum migration

References
    NIST IR 8547 IPD    draft transition dates for quantum-vulnerable algorithms
                        (112-bit security strength) and disallowed after 2035
    NIST FIPS 203/204/205  ML-KEM, ML-DSA, SLH-DSA
    CA/Browser Forum ballot SC-081v3  TLS validity 200d (2026-03-15),
                        100d (2027-03-15), 47d (2029-03-15)
    NCSA draft Quantum Security Migration Master Plan 2026-2035, section 3.3
                        cryptographic inventory / CBOM evidence for Gate A

Dependencies: cryptography (required for certificate parsing).
Optional: an `openssl` binary >= 3.5 on PATH enables real hybrid key-exchange
detection. Without it the key-exchange verdict is reported as UNKNOWN rather
than guessed — a false "quantum safe" is worse than no answer.
"""

from __future__ import annotations

import datetime as dt
import re
import shutil
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed448,
        ed25519,
        padding,
        rsa,
    )

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False


# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# NIST CSOR object identifiers for the standardised PQC algorithms.
# Verify against https://csrc.nist.gov/projects/computer-security-objects-register
# before relying on these in client-facing evidence.
PQC_SIGNATURE_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

PQC_KEM_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

# TLS 1.3 named groups that provide post-quantum protection for key exchange.
# All standardised options are hybrids: a classical curve concatenated with
# ML-KEM, so the exchange stays secure unless both are broken.
PQC_HYBRID_GROUPS: dict[str, str] = {
    "X25519MLKEM768": "hybrid, standardised",
    "SecP256r1MLKEM768": "hybrid, standardised",
    "SecP384r1MLKEM1024": "hybrid, standardised",
    "X25519Kyber768Draft00": "hybrid, pre-standard draft",
    "P256Kyber768Draft00": "hybrid, pre-standard draft",
    "x25519_kyber768": "hybrid, pre-standard draft",
}

# Order matters: the probe stops at the first group the server accepts.
KEX_PROBE_GROUPS: tuple[str, ...] = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
)

# CA/Browser Forum ballot SC-081v3 maximum validity, by certificate issue date.
CAB_VALIDITY_SCHEDULE: tuple[tuple[dt.date, int], ...] = (
    (dt.date(2029, 3, 15), 47),
    (dt.date(2027, 3, 15), 100),
    (dt.date(2026, 3, 15), 200),
    (dt.date(2020, 9, 1), 398),
)

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Ports that speak TLS immediately on connect. STARTTLS ports (25, 110, 143,
# 587, 3306, 5432) need a protocol-specific upgrade and are NOT covered here —
# absence of a result for those is not evidence of absence of TLS.
DEFAULT_TLS_PORTS: tuple[int, ...] = (443, 8443, 9443, 4443, 993, 995, 465, 636, 990, 992, 5061)


# --------------------------------------------------------------------------
# Classification helpers
# --------------------------------------------------------------------------

def rsa_security_strength(bits: int) -> int:
    """Classical security strength in bits, per NIST SP 800-57 Part 1."""
    if bits >= 15360:
        return 256
    if bits >= 7680:
        return 192
    if bits >= 3072:
        return 128
    if bits >= 2048:
        return 112
    if bits >= 1024:
        return 80
    return 0


def ec_security_strength(curve_bits: int) -> int:
    """Elliptic curve strength is roughly half the field size."""
    if curve_bits >= 512:
        return 256
    if curve_bits >= 384:
        return 192
    if curve_bits >= 256:
        return 128
    if curve_bits >= 224:
        return 112
    return 80


def cab_validity_limit(issued_on: dt.date) -> int:
    """Maximum public TLS validity in days applicable at the issue date."""
    for start, limit in CAB_VALIDITY_SCHEDULE:
        if issued_on >= start:
            return limit
    return 398


def nist_ir_8547_status(is_pqc: bool, strength: int) -> str:
    """Transition label from the NIST IR 8547 Initial Public Draft."""
    if is_pqc:
        return "PQC algorithm observed"
    if strength and strength <= 112:
        return "Draft: deprecated after 2030; disallowed after 2035"
    return "Draft: disallowed after 2035"


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------

@dataclass
class TLSFinding:
    ip: str = ""
    port: int = 0
    hostname: str = ""
    reachable: bool = False
    error: str = ""

    # negotiated connection
    tls_version: str = ""
    cipher_suite: str = ""

    # leaf certificate
    subject: str = ""
    issuer: str = ""
    san: str = ""
    serial: str = ""
    self_signed: bool = False

    # --- axis 1: validity (certificate lifecycle management) ---
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: Optional[int] = None
    validity_days: Optional[int] = None
    cab_limit_days: Optional[int] = None
    exceeds_cab_limit: bool = False
    cab_applicability: str = "Requires public-trust validation"

    # --- axis 2: algorithm (post-quantum migration) ---
    public_key_algorithm: str = ""
    public_key_size: Optional[int] = None
    signature_algorithm: str = ""
    security_strength_bits: Optional[int] = None
    quantum_vulnerable: Optional[bool] = None
    pqc_algorithm: str = ""
    nist_ir_8547: str = ""

    key_exchange_group: str = ""
    key_exchange_pqc: str = "UNKNOWN"  # PQC-PROTECTED / CLASSICAL-ONLY / UNKNOWN
    hndl_exposed: Optional[bool] = None

    # rollup
    findings: list[str] = field(default_factory=list)
    risk: str = ""

    def as_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = " | ".join(self.findings)
        return d


# --------------------------------------------------------------------------
# openssl-backed key-exchange probe
# --------------------------------------------------------------------------

_OPENSSL_CACHE: dict[str, Any] = {}


def openssl_supports_mlkem() -> bool:
    """True when an openssl binary new enough for ML-KEM groups is on PATH."""
    if "ok" in _OPENSSL_CACHE:
        return _OPENSSL_CACHE["ok"]

    ok = False
    binary = shutil.which("openssl")
    if binary:
        try:
            out = subprocess.run(
                [binary, "version"], capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", out)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                ok = (major, minor) >= (3, 5)
        except Exception:
            ok = False

    _OPENSSL_CACHE["ok"] = ok
    _OPENSSL_CACHE["bin"] = binary
    return ok


def probe_key_exchange(host: str, port: int, sni: str = "", timeout: int = 12) -> tuple[str, str]:
    """
    Determine whether the endpoint will negotiate a post-quantum hybrid group.

    Returns (group_name, verdict) where verdict is one of
    PQC-PROTECTED / CLASSICAL-ONLY / UNKNOWN.

    UNKNOWN is returned whenever the local toolchain cannot answer the
    question. It is never downgraded to CLASSICAL-ONLY, because reporting a
    host as classical when we simply could not test it would understate the
    customer's exposure in the opposite direction to a false positive.
    """
    if not openssl_supports_mlkem():
        return "", "UNKNOWN"

    binary = _OPENSSL_CACHE.get("bin") or "openssl"
    server_name = sni or host

    # 1. What does the server actually pick from a normal client hello?
    negotiated = ""
    try:
        proc = subprocess.run(
            [binary, "s_client", "-connect", f"{host}:{port}",
             "-servername", server_name, "-tls1_3", "-brief"],
            capture_output=True, text=True, timeout=timeout, input="",
        )
        blob = (proc.stdout or "") + (proc.stderr or "")
        m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", blob)
        if not m:
            m = re.search(r"Server Temp Key:\s*(\S+)", blob)
        if m:
            negotiated = m.group(1).strip()
    except Exception:
        pass

    if negotiated and any(g.lower() in negotiated.lower() for g in PQC_HYBRID_GROUPS):
        return negotiated, "PQC-PROTECTED"

    # 2. The server may support a hybrid group without preferring it.
    #    Offer each hybrid group alone and see whether the handshake completes.
    for group in KEX_PROBE_GROUPS:
        try:
            proc = subprocess.run(
                [binary, "s_client", "-connect", f"{host}:{port}",
                 "-servername", server_name, "-tls1_3",
                 "-groups", group, "-brief"],
                capture_output=True, text=True, timeout=timeout, input="",
            )
            blob = (proc.stdout or "") + (proc.stderr or "")
            if re.search(r"(Negotiated TLS1\.3 group|Protocol version|Ciphersuite)", blob) \
                    and "alert" not in blob.lower() and "failure" not in blob.lower():
                return group, "PQC-PROTECTED"
        except Exception:
            continue

    if negotiated:
        return negotiated, "CLASSICAL-ONLY"
    return "", "UNKNOWN"


# --------------------------------------------------------------------------
# Certificate inspection
# --------------------------------------------------------------------------

def _describe_public_key(cert: "x509.Certificate") -> tuple[str, Optional[int], int, bool, str]:
    """Return (algorithm, key_size, strength_bits, is_pqc, pqc_name)."""
    try:
        pub = cert.public_key()
    except Exception:
        # cryptography raises for algorithms it does not implement, which is
        # exactly what a PQC certificate looks like on an older build.
        oid = getattr(getattr(cert, "signature_algorithm_oid", None), "dotted_string", "")
        name = PQC_SIGNATURE_OIDS.get(oid, "")
        if name:
            return name, None, 128, True, name
        return "Unrecognised", None, 0, False, ""

    if isinstance(pub, rsa.RSAPublicKey):
        bits = pub.key_size
        return "RSA", bits, rsa_security_strength(bits), False, ""
    if isinstance(pub, ec.EllipticCurvePublicKey):
        bits = pub.curve.key_size
        return f"EC {pub.curve.name}", bits, ec_security_strength(bits), False, ""
    if isinstance(pub, dsa.DSAPublicKey):
        bits = pub.key_size
        return "DSA", bits, rsa_security_strength(bits), False, ""
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, 128, False, ""
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448, 224, False, ""

    return type(pub).__name__, None, 0, False, ""


def _name_to_str(name) -> str:
    try:
        return ", ".join(f"{a.oid._name}={a.value}" for a in name)
    except Exception:
        return str(name)


def _san_to_str(cert: "x509.Certificate") -> str:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ", ".join(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return ""


def _is_self_signed(cert: "x509.Certificate") -> bool:
    """Verify self-signature; subject == issuer alone only proves self-issued."""
    if cert.subject != cert.issuer:
        return False
    try:
        public_key = cert.public_key()
        signature = cert.signature
        payload = cert.tbs_certificate_bytes
        algorithm = cert.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, payload, padding.PKCS1v15(), algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(algorithm))
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, payload, algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, payload)
        else:
            return False
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------------

def scan_endpoint(
    ip: str,
    port: int = 443,
    hostname: str = "",
    timeout: int = 8,
    probe_kex: bool = True,
) -> TLSFinding:
    """
    Perform one TLS handshake and classify the result on both axes.

    This is an ordinary TLS connection — the same thing a browser does. It
    sends no payload and attempts no exploitation. Only run it against hosts
    you are authorised to assess.
    """
    f = TLSFinding(ip=ip, port=port, hostname=hostname or "")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we are inspecting, not validating trust
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    sni = hostname if hostname and not _looks_like_ip(hostname) else None

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                f.reachable = True
                f.tls_version = tls.version() or ""
                cipher = tls.cipher()
                if cipher:
                    f.cipher_suite = cipher[0]
                der = tls.getpeercert(binary_form=True)
    except Exception as exc:
        f.error = f"{type(exc).__name__}: {exc}"[:200]
        return f

    if not der or not CRYPTOGRAPHY_AVAILABLE:
        f.error = f.error or "certificate not retrieved or cryptography missing"
        return f

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        f.error = f"certificate parse failed: {exc}"[:200]
        return f

    f.subject = _name_to_str(cert.subject)
    f.issuer = _name_to_str(cert.issuer)
    f.san = _san_to_str(cert)
    f.serial = format(cert.serial_number, "x")
    f.self_signed = _is_self_signed(cert)

    # --- axis 1: validity ---
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        nb = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    now = dt.datetime.now(dt.timezone.utc)
    f.not_before = nb.date().isoformat()
    f.not_after = na.date().isoformat()
    f.days_to_expiry = (na - now).days
    f.validity_days = (na - nb).days
    f.cab_limit_days = cab_validity_limit(nb.date())
    f.exceeds_cab_limit = bool(
        f.validity_days and f.validity_days > f.cab_limit_days and not f.self_signed
    )
    if f.self_signed:
        f.cab_applicability = "Not applicable to self-signed certificate"

    # --- axis 2: algorithm ---
    alg, size, strength, is_pqc, pqc_name = _describe_public_key(cert)
    f.public_key_algorithm = alg
    f.public_key_size = size
    f.security_strength_bits = strength or None
    f.pqc_algorithm = pqc_name

    sig_oid = getattr(cert.signature_algorithm_oid, "dotted_string", "")
    sig_name = getattr(cert.signature_algorithm_oid, "_name", "") or sig_oid
    if sig_oid in PQC_SIGNATURE_OIDS:
        sig_name = PQC_SIGNATURE_OIDS[sig_oid]
        is_pqc = True
        f.pqc_algorithm = f.pqc_algorithm or sig_name
    f.signature_algorithm = sig_name

    f.quantum_vulnerable = not is_pqc
    f.nist_ir_8547 = nist_ir_8547_status(is_pqc, strength)

    # --- key exchange ---
    if probe_kex:
        group, verdict = probe_key_exchange(ip, port, sni=sni or "")
        f.key_exchange_group = group
        f.key_exchange_pqc = verdict
    if f.key_exchange_pqc == "CLASSICAL-ONLY":
        f.hndl_exposed = True
    elif f.key_exchange_pqc == "PQC-PROTECTED":
        f.hndl_exposed = False

    _apply_findings(f)
    return f


def _apply_findings(f: TLSFinding) -> None:
    notes: list[str] = []
    severity = 0

    def bump(level: int, text: str) -> None:
        nonlocal severity
        severity = max(severity, level)
        notes.append(text)

    if f.tls_version in WEAK_TLS_VERSIONS:
        bump(3, f"Negotiated obsolete protocol {f.tls_version}")
    if f.days_to_expiry is not None:
        if f.days_to_expiry < 0:
            bump(3, f"Certificate expired {abs(f.days_to_expiry)} days ago")
        elif f.days_to_expiry <= 30:
            bump(2, f"Expires in {f.days_to_expiry} days")
    if f.exceeds_cab_limit:
        notes.append(
            f"Validity {f.validity_days}d exceeds the {f.cab_limit_days}d public-TLS schedule; "
            "confirm that the certificate is publicly trusted before treating this as a CA/B finding"
        )
    if f.self_signed:
        bump(1, "Self-signed — private or untracked issuance")
    if f.security_strength_bits and f.security_strength_bits < 112:
        bump(3, f"Key below 112-bit strength ({f.public_key_algorithm} {f.public_key_size})")
    if f.quantum_vulnerable:
        bump(2 if f.nist_ir_8547 == "Deprecated after 2030" else 1,
             f"Quantum-vulnerable key ({f.public_key_algorithm}) — {f.nist_ir_8547}")
    if f.key_exchange_pqc == "CLASSICAL-ONLY":
        bump(2, "Classical-only key exchange observed — assess protected-data sensitivity and confidentiality lifetime for HNDL priority")
    elif f.key_exchange_pqc == "UNKNOWN":
        notes.append("Key exchange not tested — openssl 3.5+ unavailable")
    if f.pqc_algorithm:
        notes.append(f"Post-quantum algorithm in use: {f.pqc_algorithm}")

    f.findings = notes
    f.risk = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}[severity]


def _looks_like_ip(value: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value.strip()) is not None


def choose_tls_ports(open_ports: Iterable[int], extra: Iterable[int] = ()) -> list[int]:
    """Intersect discovered ports with ports that speak TLS on connect."""
    candidates = set(DEFAULT_TLS_PORTS) | set(extra)
    found = sorted(p for p in open_ports if p in candidates)
    if 443 not in found:
        found.insert(0, 443)  # always try 443 even if Shodan did not list it
    return found


def scan_many(
    targets: list[tuple[str, int, str]],
    max_workers: int = 12,
    timeout: int = 8,
    probe_kex: bool = True,
    progress=None,
) -> list[TLSFinding]:
    """targets is a list of (ip, port, hostname)."""
    results: list[TLSFinding] = []
    if not targets:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_endpoint, ip, port, host, timeout, probe_kex): (ip, port)
            for ip, port, host in targets
        }
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                results.append(fut.result())
            except Exception as exc:
                ip, port = futures[fut]
                results.append(TLSFinding(ip=ip, port=port, error=str(exc)[:200]))
            if progress:
                progress(i, len(futures))

    results.sort(key=lambda r: (r.ip, r.port))
    return results


def summarise(findings: list[TLSFinding]) -> dict[str, Any]:
    live = [f for f in findings if f.reachable and not f.error]
    return {
        "endpoints_tested": len(findings),
        "tls_endpoints_live": len(live),
        "quantum_vulnerable_certs": sum(1 for f in live if f.quantum_vulnerable),
        "pqc_certs": sum(1 for f in live if f.pqc_algorithm),
        "classical_only_kex": sum(1 for f in live if f.key_exchange_pqc == "CLASSICAL-ONLY"),
        "pqc_protected_kex": sum(1 for f in live if f.key_exchange_pqc == "PQC-PROTECTED"),
        "kex_untested": sum(1 for f in live if f.key_exchange_pqc == "UNKNOWN"),
        "deprecated_2030": sum(1 for f in live if f.nist_ir_8547 == "Deprecated after 2030"),
        "expiring_30d": sum(1 for f in live if f.days_to_expiry is not None and 0 <= f.days_to_expiry <= 30),
        "expired": sum(1 for f in live if f.days_to_expiry is not None and f.days_to_expiry < 0),
        "over_cab_limit": sum(1 for f in live if f.exceeds_cab_limit),
        "self_signed": sum(1 for f in live if f.self_signed),
        "weak_protocol": sum(1 for f in live if f.tls_version in WEAK_TLS_VERSIONS),
    }


if __name__ == "__main__":
    import json
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "www.cloudflare.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    result = scan_endpoint(host, port, hostname=host)
    print(json.dumps(result.as_row(), indent=2, default=str))
