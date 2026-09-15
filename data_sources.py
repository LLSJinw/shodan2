"""Read-only external data-source clients with explicit status reporting."""

from __future__ import annotations

from typing import Any

import requests


USER_AGENT = "UIH-PQC-Recon/2.0 (authorized defensive assessment)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _get(url: str, *, timeout: int = 12, **kwargs) -> requests.Response:
    headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
    return requests.get(url, timeout=timeout, headers=headers, **kwargs)


def resolve_google(domain: str) -> tuple[list[str], str]:
    try:
        response = _get("https://dns.google/resolve", params={"name": domain, "type": "A"}, timeout=6)
        response.raise_for_status()
        answers = response.json().get("Answer", [])
        return [str(answer.get("data", "")) for answer in answers if answer.get("type") == 1], "Available"
    except Exception as exc:
        return [], f"Unavailable: {type(exc).__name__}"


def fetch_dnsdumpster(domain: str, api_key: str) -> tuple[list[dict[str, Any]], str]:
    if not api_key:
        return [], "Not configured"
    try:
        response = _get(
            f"https://api.dnsdumpster.com/domain/{domain}",
            headers={"X-API-Key": api_key},
            timeout=12,
        )
        response.raise_for_status()
        records: list[dict[str, Any]] = []
        data = response.json()
        for section in ("a", "mx", "ns"):
            for record in data.get(section, []):
                for ip_entry in record.get("ips", []):
                    if ip_entry.get("ip"):
                        records.append({
                            "ip": str(ip_entry["ip"]),
                            "hostname": record.get("host", ""),
                            "record_type": section.upper(),
                            "asn": ip_entry.get("asn", ""),
                            "asn_name": ip_entry.get("asn_name", ""),
                            "country": ip_entry.get("country", ""),
                            "ptr": ip_entry.get("ptr", ""),
                        })
        return records, "Available"
    except Exception as exc:
        return [], f"Unavailable: {type(exc).__name__}"


def query_internetdb(ip: str) -> tuple[dict[str, Any], str]:
    empty = {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
    try:
        response = _get(f"https://internetdb.shodan.io/{ip}", timeout=7)
        if response.status_code == 404:
            return {**empty, "status": "No record at scan time"}, "Available - no record"
        response.raise_for_status()
        data = response.json()
        return {
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "status": "Observed",
        }, "Available"
    except Exception as exc:
        return {**empty, "status": f"Unavailable: {type(exc).__name__}"}, f"Unavailable: {type(exc).__name__}"


def _cvss_from_metrics(metrics: dict[str, Any]) -> Any:
    candidates = (
        "cvssV4_0",
        "cvssV3_1",
        "cvssV3_0",
        "cvssV2_0",
    )
    for key in candidates:
        metric = metrics.get(key)
        if not metric:
            continue
        if isinstance(metric, list):
            metric = metric[0] if metric else {}
        data = metric.get("data", metric) if isinstance(metric, dict) else {}
        score = data.get("score", data.get("baseScore")) if isinstance(data, dict) else None
        if score is not None:
            return score
    return "N/A"


def get_opencve_details(cve_id: str, username: str, password: str) -> tuple[dict[str, Any], str]:
    if not username or not password:
        return {"CVE ID": cve_id, "Title": "Details not queried", "CVSS": "N/A"}, "Not configured"
    try:
        response = _get(
            f"https://app.opencve.io/api/cve/{cve_id}",
            auth=(username, password),
            timeout=12,
        )
        if response.status_code == 404:
            return {"CVE ID": cve_id, "Title": "Not found", "CVSS": "N/A"}, "Available - no record"
        response.raise_for_status()
        data = response.json()
        title = data.get("title") or data.get("description") or "Description unavailable"
        return {"CVE ID": cve_id, "Title": title, "CVSS": _cvss_from_metrics(data.get("metrics", {}))}, "Available"
    except Exception as exc:
        return {"CVE ID": cve_id, "Title": "Source unavailable", "CVSS": "N/A"}, f"Unavailable: {type(exc).__name__}"


def fetch_kev_catalog() -> tuple[dict[str, dict[str, Any]], str]:
    try:
        response = _get(KEV_URL, timeout=15)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities", [])
        return {entry["cveID"]: entry for entry in entries if entry.get("cveID")}, "Available"
    except Exception as exc:
        return {}, f"Unavailable: {type(exc).__name__}"


def fetch_epss(cve_ids: list[str]) -> tuple[dict[str, dict[str, Any]], str]:
    if not cve_ids:
        return {}, "Not required"
    results: dict[str, dict[str, Any]] = {}
    try:
        for start in range(0, len(cve_ids), 50):
            batch = cve_ids[start:start + 50]
            response = _get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=15)
            response.raise_for_status()
            for entry in response.json().get("data", []):
                if entry.get("cve"):
                    results[entry["cve"]] = entry
        return results, "Available"
    except Exception as exc:
        return results, f"Unavailable: {type(exc).__name__}"

