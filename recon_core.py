"""Deterministic validation, enrichment, and reporting logic for PQC Recon V2."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit


MAX_INPUT_TARGETS = 10
MAX_DISCOVERED_IPS = 50
MAX_EXTRA_PORTS = 10
MAX_CVES = 100
MAX_TLS_ENDPOINTS = 100

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

EXPOSURE_PORTS = {
    21: "FTP service",
    22: "SSH administration",
    23: "Telnet administration",
    25: "SMTP service",
    445: "SMB service",
    1433: "Microsoft SQL Server",
    2375: "Docker API",
    3306: "MySQL service",
    3389: "Remote Desktop",
    5432: "PostgreSQL service",
    5900: "VNC remote access",
    6379: "Redis service",
    6443: "Kubernetes API",
    9200: "Elasticsearch service",
    27017: "MongoDB service",
}

PRIORITY_ORDER = {"Urgent": 0, "High": 1, "Medium": 2, "Review": 3, "Informational": 4}


@dataclass(frozen=True)
class Target:
    original: str
    kind: str
    value: str


@dataclass
class Finding:
    finding_id: str
    priority: str
    domain: str
    asset: str
    observation: str
    evidence: str
    confidence: str
    why_it_matters: str
    customer_validation: str
    suggested_next_step: str

    def as_row(self) -> dict[str, Any]:
        return {
            "Finding ID": self.finding_id,
            "Priority": self.priority,
            "Domain": self.domain,
            "Asset": self.asset,
            "Observation": self.observation,
            "Evidence": self.evidence,
            "Confidence": self.confidence,
            "Why it matters": self.why_it_matters,
            "Customer validation": self.customer_validation,
            "Suggested next step": self.suggested_next_step,
        }


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def normalize_target(raw: str) -> Target:
    value = raw.strip()
    if not value:
        raise ValueError("Empty target")

    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    host = host.strip().rstrip(".").lower()

    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private, loopback, link-local, multicast, and reserved addresses are blocked")
        return Target(original=value, kind="ip", value=str(ip))
    except ValueError as exc:
        if any(token in str(exc) for token in ("Private", "loopback", "reserved")):
            raise

    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError("Invalid IP address")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name") from exc
    if not DOMAIN_RE.fullmatch(ascii_host) or ascii_host.endswith(".local"):
        raise ValueError("Enter a public IP address or a valid fully qualified domain name")
    return Target(original=value, kind="domain", value=ascii_host)


def parse_targets(text: str, limit: int = MAX_INPUT_TARGETS) -> tuple[list[Target], list[dict[str, str]]]:
    accepted: list[Target] = []
    rejected: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    for raw in lines:
        try:
            target = normalize_target(raw)
            key = (target.kind, target.value)
            if key in seen:
                continue
            if len(accepted) >= limit:
                rejected.append({"Target": raw, "Reason": f"Input limit is {limit} unique targets per run"})
                continue
            accepted.append(target)
            seen.add(key)
        except ValueError as exc:
            rejected.append({"Target": raw, "Reason": str(exc)})
    return accepted, rejected


def parse_extra_ports(text: str, limit: int = MAX_EXTRA_PORTS) -> tuple[list[int], list[str]]:
    ports: list[int] = []
    rejected: list[str] = []
    for chunk in text.split(","):
        value = chunk.strip()
        if not value:
            continue
        if not value.isdigit() or not 1 <= int(value) <= 65535:
            rejected.append(value)
            continue
        port = int(value)
        if port not in ports and len(ports) < limit:
            ports.append(port)
        elif port not in ports:
            rejected.append(value)
    return ports, rejected


def public_ip_values(values: Iterable[str]) -> tuple[list[str], list[str]]:
    accepted: list[str] = []
    rejected: list[str] = []
    for value in values:
        if is_public_ip(value):
            accepted.append(str(ipaddress.ip_address(value)))
        else:
            rejected.append(value)
    return list(dict.fromkeys(accepted)), list(dict.fromkeys(rejected))


def group_relations(relations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for relation in relations:
        ip = relation["ip"]
        item = grouped.setdefault(
            ip,
            {
                "ip": ip,
                "inputs": set(),
                "hostnames": set(),
                "sources": set(),
                "record_types": set(),
                "asn": "",
                "asn_name": "",
                "country": "",
                "ptr": "",
            },
        )
        for key, field in (("input", "inputs"), ("hostname", "hostnames"), ("source", "sources"), ("record_type", "record_types")):
            if relation.get(key):
                item[field].add(relation[key])
        for field in ("asn", "asn_name", "country", "ptr"):
            if relation.get(field) and not item[field]:
                item[field] = relation[field]
    return grouped


def technical_priority(cvss: Any, kev: bool, epss: Any) -> str:
    try:
        cvss_value = float(cvss)
    except (TypeError, ValueError):
        cvss_value = 0.0
    try:
        epss_value = float(epss)
    except (TypeError, ValueError):
        epss_value = 0.0

    if kev:
        return "Urgent"
    if cvss_value >= 9.0 or epss_value >= 0.5:
        return "High"
    if cvss_value >= 7.0 or epss_value >= 0.1:
        return "Medium"
    return "Review"


def build_findings(
    asset_rows: list[dict[str, Any]],
    cve_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[Finding] = []
    sequence = defaultdict(int)

    def next_id(domain: str) -> str:
        sequence[domain] += 1
        return f"{domain}-{sequence[domain]:03d}"

    for row in cve_rows:
        priority = row.get("Technical Priority", "Review")
        kev = row.get("CISA KEV") == "Yes"
        epss = row.get("EPSS")
        evidence = f"Shodan InternetDB association; {row.get('CVE ID', '')}"
        if kev:
            evidence += "; CISA KEV"
        if epss not in (None, "", "N/A"):
            evidence += f"; EPSS {epss}"
        findings.append(Finding(
            next_id("VULN"), priority, "Vulnerability", row.get("IP", ""),
            f"External telemetry associates {row.get('CVE ID', 'a CVE')} with this exposed asset.",
            evidence,
            "Medium - external observation requires product/version validation",
            "Known exploitation or high exploit likelihood can increase remediation urgency.",
            "Confirm the exposed product, version, ownership, and whether the CVE is applicable.",
            "Validate against authenticated inventory and vendor advisory before proposing remediation.",
        ))

    for row in asset_rows:
        ip = row.get("IP", "")
        ports = row.get("Ports", [])
        for port in ports:
            if port not in EXPOSURE_PORTS:
                continue
            service = EXPOSURE_PORTS[port]
            findings.append(Finding(
                next_id("EXP"), "Review", "Attack surface", f"{ip}:{port}",
                f"{service} is reported as internet accessible.",
                f"Shodan InternetDB open-port observation for TCP/{port}",
                "Medium - externally observed service",
                "Administrative and data services may create unnecessary exposure when not intentionally published.",
                "Is this service required externally, who owns it, and what access controls protect it?",
                "Confirm exposure from an authorized validation point and restrict access where unnecessary.",
            ))

    risk_to_priority = {"High": "High", "Medium": "Medium", "Low": "Review", "Info": "Informational"}
    for row in tls_rows:
        if not row.get("reachable") or row.get("error"):
            continue
        notes = [part.strip() for part in str(row.get("findings", "")).split("|") if part.strip()]
        if not notes:
            continue
        endpoint = f"{row.get('hostname') or row.get('ip')}:{row.get('port')}"
        findings.append(Finding(
            next_id("TLS"), risk_to_priority.get(row.get("risk"), "Review"), "TLS / PQC", endpoint,
            "; ".join(notes),
            f"Active TLS handshake; {row.get('tls_version', 'version unknown')} / {row.get('cipher_suite', 'cipher unknown')}",
            "High for observed certificate; contextual impact requires customer validation",
            "Certificate lifecycle and cryptographic migration issues can affect availability, trust, and long-lived confidentiality.",
            "Confirm certificate ownership, trust model, protected data type, and required confidentiality lifetime.",
            "Add the endpoint to the cryptographic inventory and assign lifecycle or PQC migration action as applicable.",
        ))

    findings.sort(key=lambda item: (PRIORITY_ORDER.get(item.priority, 9), item.finding_id))
    return [finding.as_row() for finding in findings]


def flatten_grouped_assets(grouped: dict[str, dict[str, Any]], observations: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ip, item in sorted(grouped.items()):
        observation = observations.get(ip, {})
        ports = sorted({int(port) for port in observation.get("ports", []) if str(port).isdigit()})
        rows.append({
            "IP": ip,
            "Hostnames": ", ".join(sorted(item["hostnames"])),
            "Original inputs": ", ".join(sorted(item["inputs"])),
            "Discovery sources": ", ".join(sorted(item["sources"])),
            "Record types": ", ".join(sorted(item["record_types"])),
            "Ports": ports,
            "Open TCP ports": ", ".join(map(str, ports)) or "None reported",
            "CVE count": len(observation.get("vulns", [])),
            "CPEs": ", ".join(observation.get("cpes", [])),
            "InternetDB hostnames": ", ".join(observation.get("hostnames", [])),
            "Tags": ", ".join(observation.get("tags", [])),
            "ASN": item["asn"],
            "ASN name": item["asn_name"],
            "Country": item["country"],
            "PTR": item["ptr"],
            "InternetDB status": observation.get("status", "Not queried"),
        })
    return rows
