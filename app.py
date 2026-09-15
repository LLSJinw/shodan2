from __future__ import annotations

import datetime as dt
import html
import os
from collections import Counter
from typing import Any

import pandas as pd
import streamlit as st

import data_sources
import demo_data
import pqc_tls
import recon_core
import reporting


st.set_page_config(
    page_title="External Exposure & PQC Readiness",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)


def secret(name: str) -> str:
    try:
        return str(st.secrets.get(name, ""))
    except Exception:
        return os.getenv(name.upper(), "")


DNSDUMPSTER_API_KEY = secret("dnsdumpster_api_key")
OPENCVE_USER = secret("opencve_user")
OPENCVE_PASS = secret("opencve_pass")

PROFILE_STANDARD = "Standard presales"
PROFILE_QUICK = "Quick discovery"
PROFILE_FOCUSED = "Focused TLS and PQC"
PROFILE_CUSTOM = "Custom"
PROFILE_ORDER = (PROFILE_STANDARD, PROFILE_QUICK, PROFILE_FOCUSED, PROFILE_CUSTOM)
PROFILE_HELP = {
    PROFILE_STANDARD: "Recommended for most presales work. Discovers exposure, enriches CVEs, and assesses TLS and PQC in one run.",
    PROFILE_QUICK: "Fast first round. Maps public assets, services, and CVE associations without active TLS checks.",
    PROFILE_FOCUSED: "Second round for certificate lifecycle, TLS posture, and hybrid key exchange on discovered or selected ports.",
    PROFILE_CUSTOM: "Expert mode. Manually control TLS, key-exchange probing, timeouts, concurrency, and additional ports.",
}


@st.cache_data(ttl=1800, show_spinner=False)
def cached_google_dns(domain: str):
    return data_sources.resolve_google(domain)


@st.cache_data(ttl=1800, show_spinner=False)
def cached_dnsdumpster(domain: str, api_key: str):
    return data_sources.fetch_dnsdumpster(domain, api_key)


@st.cache_data(ttl=1800, show_spinner=False)
def cached_internetdb(ip: str):
    return data_sources.query_internetdb(ip)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_opencve(cve_id: str, username: str, password: str):
    return data_sources.get_opencve_details(cve_id, username, password)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_kev():
    return data_sources.fetch_kev_catalog()


@st.cache_data(ttl=3600, show_spinner=False)
def cached_epss(cve_ids: tuple[str, ...]):
    return data_sources.fetch_epss(list(cve_ids))


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root { --ink:#192c36; --muted:#62727b; --line:#dfe6e8; --teal:#087f73; --pale:#eef7f5; --amber:#a96c17; --red:#b74d46; }
        .stApp { background:#f5f7f8; color:var(--ink); }
        [data-testid="stHeader"] { background:rgba(245,247,248,.94); }
        [data-testid="stSidebar"] { background:#202d36; }
        [data-testid="stSidebar"] * { color:#edf3f4; }
        [data-testid="stSidebar"] [data-testid="stAlert"] * { color:inherit; }
        .block-container { max-width:1400px; padding-top:3.2rem; padding-bottom:4rem; }
        h1,h2,h3 { letter-spacing:0 !important; color:var(--ink); }
        h1 { font-size:2rem !important; line-height:1.08 !important; }
        h2 { font-size:1.25rem !important; }
        h3 { font-size:1rem !important; }
        .product-header { display:flex; justify-content:space-between; align-items:flex-start; gap:24px; margin:0 0 18px; }
        .product-header h1 { margin:0 0 7px; }
        .product-header p { max-width:780px; margin:0; color:var(--muted); font-size:.92rem; }
        .method-badge { flex:0 0 auto; padding:7px 9px; color:#07685f; background:#e2f2ef; border:1px solid #bdded8; border-radius:6px; font-size:.72rem; font-weight:700; }
        .section-kicker { margin:0 0 4px; color:var(--teal); font-size:.7rem; font-weight:800; text-transform:uppercase; }
        .result-context { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 14px; }
        .context-chip { padding:5px 8px; color:#40535d; background:white; border:1px solid var(--line); border-radius:5px; font-size:.72rem; }
        div[data-testid="stVerticalBlockBorderWrapper"] { border-color:var(--line); border-radius:7px; background:white; }
        div[data-testid="stMetric"] { min-height:106px; padding:14px; background:white; border:1px solid var(--line); border-radius:7px; }
        div[data-testid="stMetricLabel"] { color:var(--muted); }
        div[data-testid="stMetricValue"] { color:var(--ink); font-size:1.65rem; }
        .finding-summary { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:8px; margin:8px 0 16px; }
        .finding-summary div { padding:10px 12px; background:white; border:1px solid var(--line); border-left:3px solid #788991; border-radius:6px; }
        .finding-summary div:nth-child(1) { border-left-color:var(--red); }.finding-summary div:nth-child(2) { border-left-color:#c47a26; }
        .finding-summary strong,.finding-summary small { display:block; }.finding-summary strong { font-size:1.2rem; }.finding-summary small { margin-top:2px; color:var(--muted); font-size:.68rem; }
        .finding-list { display:grid; gap:9px; }
        .finding-row { padding:12px 14px; background:white; border:1px solid var(--line); border-left:4px solid #788991; border-radius:6px; }
        .finding-row.urgent { border-left-color:var(--red); }.finding-row.high { border-left-color:#c47a26; }.finding-row.medium { border-left-color:#b48a2c; }
        .finding-head { display:flex; flex-wrap:wrap; align-items:center; gap:7px; margin-bottom:7px; }
        .finding-priority { padding:2px 6px; border-radius:4px; background:#eef2f3; color:#40535d; font-size:.66rem; font-weight:800; text-transform:uppercase; }
        .finding-id { color:var(--muted); font-size:.7rem; font-weight:700; }
        .finding-asset { margin-left:auto; color:#40535d; font-size:.72rem; }
        .finding-observation { margin:0 0 8px; color:var(--ink); font-size:.86rem; line-height:1.45; }
        .finding-detail { display:grid; grid-template-columns:1fr 1fr; gap:10px; color:#52636c; font-size:.73rem; line-height:1.45; }
        .finding-detail strong { display:block; margin-bottom:2px; color:#31454f; font-size:.66rem; text-transform:uppercase; }
        .health-list { display:grid; gap:6px; }
        .health-row { display:grid; grid-template-columns:minmax(0,.8fr) minmax(0,.75fr) minmax(0,1.6fr); gap:8px; padding:9px 10px; background:white; border:1px solid var(--line); border-radius:5px; font-size:.72rem; line-height:1.4; }
        .health-row span { min-width:0; overflow-wrap:anywhere; }.health-source { color:var(--ink); font-weight:700; }.health-state { color:#087f73; font-weight:700; }.health-detail { color:var(--muted); }
        .workflow-steps { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:0; margin:4px 0 18px; border:1px solid var(--line); border-radius:7px; overflow:hidden; background:white; }
        .workflow-step { display:flex; align-items:center; gap:9px; min-width:0; min-height:68px; padding:10px 12px; border-right:1px solid var(--line); }
        .workflow-step div { min-width:0; }
        .workflow-step:last-child { border-right:0; }.workflow-step span { display:grid; place-items:center; flex:0 0 27px; height:27px; border-radius:50%; color:#52636c; background:#edf1f2; font-size:.74rem; font-weight:800; }
        .workflow-step strong,.workflow-step small { display:block; }.workflow-step strong { color:var(--ink); font-size:.78rem; }.workflow-step small { margin-top:2px; color:var(--muted); font-size:.65rem; line-height:1.3; }
        .workflow-step.done span { color:white; background:var(--teal); }.workflow-step.active { background:#eef7f5; }.workflow-step.active span { color:white; background:var(--teal); }
        .profile-note { margin:8px 0 2px; padding:10px 11px; color:#dce9eb; background:#2b3b45; border-left:3px solid #2aa897; border-radius:5px; font-size:.74rem; line-height:1.5; }
        .next-action { margin:2px 0 12px; padding:12px 14px; background:#eef7f5; border-left:4px solid var(--teal); border-radius:6px; color:#34515a; font-size:.8rem; line-height:1.5; }
        .next-action strong { color:var(--ink); }
        .boundary-note { padding:12px 14px; color:#40545e; background:#eef4f6; border-left:3px solid #36748f; border-radius:5px; font-size:.78rem; line-height:1.55; }
        .source-ok { color:#087f73; font-weight:700; }.source-warn { color:#a96c17; font-weight:700; }
        button[kind="primary"] { border-radius:6px; background:var(--teal); border-color:var(--teal); }
        button[kind="secondary"] { border-radius:6px; }
        [data-baseweb="tab-list"] { gap:8px; }
        [data-baseweb="tab"] { min-height:42px; padding:0 12px; }
        @media(max-width:900px) { .product-header { flex-direction:column; }.finding-summary { grid-template-columns:1fr 1fr; }.finding-detail { grid-template-columns:1fr; }.finding-asset { width:100%; margin-left:0; }.health-row { grid-template-columns:1fr; gap:2px; }.workflow-steps { grid-template-columns:1fr 1fr; }.workflow-step:nth-child(2) { border-right:0; }.workflow-step:nth-child(-n+2) { border-bottom:1px solid var(--line); } }
        @media(max-width:560px) { .finding-summary { grid-template-columns:1fr; }.workflow-steps { grid-template-columns:1fr; }.workflow-step { border-right:0; border-bottom:1px solid var(--line); }.workflow-step:last-child { border-bottom:0; } }
        </style>
        """,
        unsafe_allow_html=True,
    )


def add_health(rows: list[dict[str, str]], source: str, status: str, detail: str) -> None:
    rows.append({"Source": source, "Status": status, "Detail": detail})


def profile_parameters(profile: str) -> tuple[bool, bool, int, int, str]:
    if profile == PROFILE_QUICK:
        return False, False, 6, 8, ""
    if profile == PROFILE_FOCUSED:
        return True, True, 12, 6, st.session_state.get("extra_tls_ports_input", "")
    if profile == PROFILE_CUSTOM:
        return (
            st.session_state.get("custom_do_tls", True),
            st.session_state.get("custom_probe_kex", True),
            st.session_state.get("custom_tls_timeout", 8),
            st.session_state.get("custom_tls_workers", 8),
            st.session_state.get("custom_extra_ports", ""),
        )
    return True, True, 8, 8, ""


def workflow_steps(has_result: bool) -> str:
    steps = (
        ("1", "Set scope", "Customer and authorized targets"),
        ("2", "Discover", "External evidence and TLS checks"),
        ("3", "Validate", "Confirm ownership and applicability"),
        ("4", "Export", "Word report and Excel evidence"),
    )
    rendered = []
    for index, (number, title, detail) in enumerate(steps):
        state = "done" if has_result and index < 2 else "active" if (has_result and index == 2) or (not has_result and index == 0) else ""
        rendered.append(
            f"<div class='workflow-step {state}'><span>{number}</span><div><strong>{title}</strong><small>{detail}</small></div></div>"
        )
    return "<div class='workflow-steps'>" + "".join(rendered) + "</div>"


def run_scan(
    customer: str,
    engagement: str,
    scope: str,
    target_text: str,
    do_tls: bool,
    probe_kex: bool,
    tls_timeout: int,
    tls_workers: int,
    extra_ports_text: str,
    profile_name: str,
) -> dict[str, Any] | None:
    accepted, rejected = recon_core.parse_targets(target_text)
    extra_ports, rejected_ports = recon_core.parse_extra_ports(extra_ports_text)
    for port in rejected_ports:
        rejected.append({"Target": port, "Reason": "Invalid or excess TLS port"})
    if not accepted:
        st.error("No safe public targets were accepted. Review the rejected-target list.")
        if rejected:
            st.dataframe(pd.DataFrame(rejected), width="stretch", hide_index=True)
        return None

    started = dt.datetime.now(dt.timezone.utc)
    relations: list[dict[str, Any]] = []
    source_health: list[dict[str, str]] = []

    with st.status("Building authorized external scope", expanded=True) as status:
        status.write(f"Accepted {len(accepted)} unique target(s).")
        for target in accepted:
            if target.kind == "ip":
                relations.append({
                    "input": target.original, "hostname": "", "ip": target.value,
                    "source": "Direct input", "record_type": "IP", "asn": "",
                    "asn_name": "", "country": "", "ptr": "",
                })
                continue

            resolved, dns_status = cached_google_dns(target.value)
            public, blocked = recon_core.public_ip_values(resolved)
            add_health(source_health, "Google DNS", dns_status, f"{target.value}: {len(public)} public A record(s)")
            for blocked_ip in blocked:
                rejected.append({"Target": blocked_ip, "Reason": f"Blocked non-public address resolved from {target.value}"})
            for ip in public:
                relations.append({
                    "input": target.original, "hostname": target.value, "ip": ip,
                    "source": "Google DNS", "record_type": "A", "asn": "",
                    "asn_name": "", "country": "", "ptr": "",
                })

            dnsdump_rows, dump_status = cached_dnsdumpster(target.value, DNSDUMPSTER_API_KEY)
            add_health(source_health, "DNSDumpster", dump_status, f"{target.value}: {len(dnsdump_rows)} record(s) returned")
            for row in dnsdump_rows:
                if not recon_core.is_public_ip(row["ip"]):
                    rejected.append({"Target": row["ip"], "Reason": f"Blocked non-public DNSDumpster result for {target.value}"})
                    continue
                relations.append({"input": target.original, "source": "DNSDumpster", **row})

        grouped = recon_core.group_relations(relations)
        if len(grouped) > recon_core.MAX_DISCOVERED_IPS:
            allowed = set(sorted(grouped)[:recon_core.MAX_DISCOVERED_IPS])
            rejected.append({
                "Target": f"{len(grouped) - len(allowed)} discovered IPs",
                "Reason": f"Run capped at {recon_core.MAX_DISCOVERED_IPS} public IPs",
            })
            grouped = {ip: value for ip, value in grouped.items() if ip in allowed}
        if not grouped:
            status.update(label="No public assets discovered", state="error")
            st.error("No public IP addresses were discovered from the accepted scope.")
            return None
        status.write(f"Enumerated {len(grouped)} public IP asset(s).")

        observations: dict[str, dict[str, Any]] = {}
        internetdb_states: list[str] = []
        for ip in sorted(grouped):
            observation, source_state = cached_internetdb(ip)
            observations[ip] = observation
            internetdb_states.append(source_state)
        internetdb_status = "Available" if any(state.startswith("Available") for state in internetdb_states) else "Unavailable"
        add_health(source_health, "Shodan InternetDB", internetdb_status, f"Queried {len(grouped)} public IP(s)")
        asset_rows = recon_core.flatten_grouped_assets(grouped, observations)
        status.write("Collected external service and CVE associations.")

        cve_ids = sorted({cve for observation in observations.values() for cve in observation.get("vulns", [])})
        if len(cve_ids) > recon_core.MAX_CVES:
            rejected.append({"Target": f"{len(cve_ids) - recon_core.MAX_CVES} CVEs", "Reason": f"Enrichment capped at {recon_core.MAX_CVES} CVEs"})
            cve_ids = cve_ids[:recon_core.MAX_CVES]
        kev_catalog, kev_status = cached_kev()
        epss_map, epss_status = cached_epss(tuple(cve_ids))
        add_health(source_health, "CISA KEV", kev_status, f"Matched against {len(cve_ids)} CVE association(s)")
        add_health(source_health, "FIRST EPSS", epss_status, f"Requested {len(cve_ids)} CVE score(s)")

        cve_rows: list[dict[str, Any]] = []
        opencve_states: list[str] = []
        for ip, observation in observations.items():
            for cve_id in sorted(set(observation.get("vulns", [])) & set(cve_ids)):
                details, detail_status = cached_opencve(cve_id, OPENCVE_USER, OPENCVE_PASS)
                opencve_states.append(detail_status)
                kev = kev_catalog.get(cve_id, {})
                epss = epss_map.get(cve_id, {})
                epss_score = epss.get("epss", "N/A")
                row = {
                    "IP": ip,
                    "CVE ID": cve_id,
                    "Title": details.get("Title", ""),
                    "CVSS": details.get("CVSS", "N/A"),
                    "CISA KEV": "Yes" if kev else "No",
                    "Known ransomware use": kev.get("knownRansomwareCampaignUse", "Unknown"),
                    "KEV date added": kev.get("dateAdded", ""),
                    "EPSS": epss_score,
                    "EPSS percentile": epss.get("percentile", "N/A"),
                }
                row["Technical Priority"] = recon_core.technical_priority(row["CVSS"], bool(kev), epss_score)
                cve_rows.append(row)
        if not OPENCVE_USER or not OPENCVE_PASS:
            open_status = "Not configured"
        elif any(state == "Available" for state in opencve_states):
            open_status = "Available"
        else:
            open_status = "Unavailable"
        add_health(source_health, "OpenCVE", open_status, f"Requested details for {len(cve_ids)} unique CVE(s)")

        tls_rows: list[dict[str, Any]] = []
        tls_summary: dict[str, Any] = {}
        if do_tls:
            tls_targets: list[tuple[str, int, str]] = []
            for ip, asset in grouped.items():
                hostnames = sorted(asset["hostnames"]) or [""]
                ports = pqc_tls.choose_tls_ports(observations[ip].get("ports", []), extra_ports)
                for hostname in hostnames:
                    for port in ports:
                        tls_targets.append((ip, port, hostname))
            tls_targets = list(dict.fromkeys(tls_targets))[:recon_core.MAX_TLS_ENDPOINTS]
            status.write(f"Assessing {len(tls_targets)} TLS endpoint and SNI combination(s).")
            findings = pqc_tls.scan_many(
                tls_targets,
                max_workers=tls_workers,
                timeout=tls_timeout,
                probe_kex=probe_kex,
            )
            tls_rows = [finding.as_row() for finding in findings]
            tls_summary = pqc_tls.summarise(findings)
            add_health(
                source_health,
                "Active TLS handshake",
                "Available",
                f"{tls_summary.get('tls_endpoints_live', 0)} of {len(tls_targets)} endpoint combinations responded",
            )
        else:
            add_health(source_health, "Active TLS handshake", "Disabled", "TLS/PQC assessment was not selected")

        finding_rows = recon_core.build_findings(asset_rows, cve_rows, tls_rows)
        completed = dt.datetime.now(dt.timezone.utc)
        summary = {
            "public_ips": len(asset_rows),
            "open_ports": sum(len(row.get("Ports", [])) for row in asset_rows),
            "cve_associations": len(cve_rows),
            "kev_matches": sum(1 for row in cve_rows if row.get("CISA KEV") == "Yes"),
            "tls_endpoints": tls_summary.get("tls_endpoints_live", 0),
            "quantum_vulnerable_certs": tls_summary.get("quantum_vulnerable_certs", 0),
            "classical_only_kex": tls_summary.get("classical_only_kex", 0),
            "pqc_protected_kex": tls_summary.get("pqc_protected_kex", 0),
            "unknown_kex": tls_summary.get("kex_untested", 0),
            "urgent_findings": sum(1 for row in finding_rows if row["Priority"] == "Urgent"),
            "high_findings": sum(1 for row in finding_rows if row["Priority"] == "High"),
        }
        status.update(label="Assessment complete", state="complete", expanded=False)

    return {
        "meta": {
            "customer": customer.strip() or "Sanitized account",
            "engagement": engagement.strip() or "External exposure review",
            "scope": scope.strip() or "Authorized targets supplied for this run",
            "started_at": started.isoformat(timespec="seconds"),
            "completed_at": completed.isoformat(timespec="seconds"),
            "tool_version": "2.0.0",
            "profile": profile_name,
            "normalized_targets": [target.value for target in accepted],
            "method": "External telemetry plus ordinary TLS handshakes; no exploitation",
        },
        "summary": summary,
        "asset_rows": asset_rows,
        "cve_rows": cve_rows,
        "tls_rows": tls_rows,
        "tls_summary": tls_summary,
        "findings": finding_rows,
        "source_health": source_health,
        "rejected_targets": rejected,
    }


def priority_summary(findings: list[dict[str, Any]]) -> str:
    counts = Counter(row.get("Priority", "Review") for row in findings)
    return "".join(
        f"<div><strong>{counts.get(level, 0)}</strong><small>{level}</small></div>"
        for level in ("Urgent", "High", "Medium", "Review")
    )


def finding_rows(findings: list[dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        priority = str(finding.get("Priority", "Review"))
        rows.append(
            f"<article class='finding-row {html.escape(priority.lower())}'>"
            "<div class='finding-head'>"
            f"<span class='finding-priority'>{html.escape(priority)}</span>"
            f"<span class='finding-id'>{html.escape(str(finding.get('Finding ID', '')))} &middot; {html.escape(str(finding.get('Domain', '')))}</span>"
            f"<span class='finding-asset'>{html.escape(str(finding.get('Asset', '')))}</span>"
            "</div>"
            f"<p class='finding-observation'>{html.escape(str(finding.get('Observation', '')))}</p>"
            "<div class='finding-detail'>"
            f"<div><strong>Validate with customer</strong>{html.escape(str(finding.get('Customer validation', '')))}</div>"
            f"<div><strong>Suggested next step</strong>{html.escape(str(finding.get('Suggested next step', '')))}</div>"
            "</div></article>"
        )
    return "<div class='finding-list'>" + "".join(rows) + "</div>"


def health_rows(health: list[dict[str, Any]]) -> str:
    rows = []
    for item in health:
        rows.append(
            "<div class='health-row'>"
            f"<span class='health-source'>{html.escape(str(item.get('Source', '')))}</span>"
            f"<span class='health-state'>{html.escape(str(item.get('Status', '')))}</span>"
            f"<span class='health-detail'>{html.escape(str(item.get('Detail', '')))}</span>"
            "</div>"
        )
    return "<div class='health-list'>" + "".join(rows) + "</div>"


def prepare_tls_follow_up(result: dict[str, Any]) -> None:
    ports = sorted({
        int(port)
        for asset in result.get("asset_rows", [])
        for port in asset.get("Ports", [])
        if int(port) in pqc_tls.DEFAULT_TLS_PORTS and int(port) != 443
    })
    meta = result.get("meta", {})
    st.session_state["assessment_profile"] = PROFILE_FOCUSED
    st.session_state["customer_input"] = meta.get("customer", "")
    st.session_state["engagement_input"] = "Focused TLS and PQC follow-up"
    st.session_state["scope_input"] = f"{meta.get('scope', '').rstrip('.')} Follow-up based on initial external discovery."
    st.session_state["targets_input"] = "\n".join(meta.get("normalized_targets", []))
    st.session_state["extra_tls_ports_input"] = ", ".join(map(str, ports))
    st.session_state["authorized_input"] = False
    st.session_state["followup_prepared"] = True


def display_results(result: dict[str, Any]) -> None:
    meta = result["meta"]
    summary = result["summary"]
    st.markdown("<p class='section-kicker'>Latest completed assessment</p>", unsafe_allow_html=True)
    st.subheader(meta["customer"])
    chips = (meta["engagement"], meta["completed_at"], f"Tool {meta['tool_version']}")
    st.markdown(
        "<div class='result-context'>" + "".join(f"<span class='context-chip'>{html.escape(value)}</span>" for value in chips) + "</div>",
        unsafe_allow_html=True,
    )

    metrics = (
        ("Public IPs", summary["public_ips"], "Observed scope"),
        ("Open services", summary["open_ports"], "InternetDB reported"),
        ("CVE associations", summary["cve_associations"], "Validation required"),
        ("CISA KEV", summary["kev_matches"], "Known exploited"),
        ("TLS endpoints", summary["tls_endpoints"], "Handshake successful"),
        ("Classical-only KEX", summary["classical_only_kex"], f"{summary['unknown_kex']} unknown"),
    )
    for metric_row in (metrics[:3], metrics[3:]):
        metric_columns = st.columns(3)
        for column, (label, value, help_text) in zip(metric_columns, metric_row):
            column.metric(label, value, help=help_text)

    st.markdown(f"<div class='finding-summary'>{priority_summary(result['findings'])}</div>", unsafe_allow_html=True)

    if meta.get("profile") == PROFILE_QUICK:
        candidate_ports = sorted({
            int(port)
            for asset in result.get("asset_rows", [])
            for port in asset.get("Ports", [])
            if int(port) in pqc_tls.DEFAULT_TLS_PORTS
        })
        port_text = ", ".join(map(str, candidate_ports)) or "443"
        st.markdown(
            f"<div class='next-action'><strong>Next recommended round:</strong> validate the discovered assets, then assess TLS and PQC on candidate ports {html.escape(port_text)}.</div>",
            unsafe_allow_html=True,
        )
        st.button(
            "Prepare focused TLS and PQC follow-up",
            on_click=prepare_tls_follow_up,
            args=(result,),
            width="stretch",
        )
    else:
        st.markdown(
            "<div class='next-action'><strong>Next action:</strong> review the priority findings with the customer, confirm ownership and applicability, then export the evidence package.</div>",
            unsafe_allow_html=True,
        )

    overview_tab, assets_tab, vulnerabilities_tab, tls_tab, report_tab = st.tabs(
        ["Overview", "Assets", "Vulnerabilities", "TLS & PQC", "Report"]
    )
    with overview_tab:
        left, right = st.columns([1.8, 1])
        with left:
            st.markdown("### Prioritized findings")
            if result["findings"]:
                st.markdown(finding_rows(result["findings"]), unsafe_allow_html=True)
            else:
                st.success("No prioritized findings were generated from the available observations.")
        with right:
            st.markdown("### Evidence coverage")
            st.markdown(health_rows(result["source_health"]), unsafe_allow_html=True)
            if result["rejected_targets"]:
                with st.expander(f"Blocked or excluded items ({len(result['rejected_targets'])})"):
                    st.dataframe(pd.DataFrame(result["rejected_targets"]), width="stretch", hide_index=True)
        st.markdown(
            "<div class='boundary-note'><strong>Interpretation boundary:</strong> External telemetry identifies leads for validation. "
            "It does not prove ownership, current product version, exploitability, business impact, or absence of vulnerabilities.</div>",
            unsafe_allow_html=True,
        )

    with assets_tab:
        st.markdown("### External asset inventory")
        asset_frame = pd.DataFrame([{key: value for key, value in row.items() if key != "Ports"} for row in result["asset_rows"]])
        st.dataframe(asset_frame, width="stretch", hide_index=True)
        st.caption("One row per public IP. Multiple input domains, discovered hostnames, and evidence sources are retained.")

    with vulnerabilities_tab:
        st.markdown("### Vulnerability observations")
        if result["cve_rows"]:
            st.dataframe(
                pd.DataFrame(result["cve_rows"]),
                width="stretch",
                hide_index=True,
                column_order=["Technical Priority", "IP", "CVE ID", "CISA KEV", "EPSS", "CVSS", "Title", "Known ransomware use"],
            )
        else:
            st.info("No CVE associations were reported by Shodan InternetDB at scan time. This is not evidence that the assets are vulnerability-free.")
        st.caption("Technical priority uses KEV, EPSS, and CVSS. Customer asset criticality and applicability must still be validated.")

    with tls_tab:
        st.markdown("### TLS lifecycle and post-quantum readiness")
        if result["tls_rows"]:
            tls_frame = pd.DataFrame(result["tls_rows"])
            visible_columns = [
                "ip", "port", "hostname", "reachable", "tls_version", "not_after", "days_to_expiry",
                "public_key_algorithm", "public_key_size", "security_strength_bits", "nist_ir_8547",
                "key_exchange_group", "key_exchange_pqc", "risk", "findings", "error",
            ]
            st.dataframe(tls_frame[[column for column in visible_columns if column in tls_frame]], width="stretch", hide_index=True)
        else:
            st.info("No TLS/PQC results are available for this run.")
        st.markdown(
            "<div class='boundary-note'><strong>Two independent axes:</strong> certificate validity indicates lifecycle risk; "
            "certificate and key-exchange algorithms indicate migration exposure. HNDL urgency additionally depends on data sensitivity and confidentiality lifetime.</div>",
            unsafe_allow_html=True,
        )

    with report_tab:
        st.markdown("### Customer-ready evidence package")
        st.write("The report is deterministic: it uses observed data, fixed classification logic, and explicit limitations. It does not generate unsupported AI conclusions.")
        excel_bytes = reporting.build_excel(result).getvalue()
        docx_bytes = reporting.build_docx(result).getvalue()
        safe_customer = "".join(character if character.isalnum() else "-" for character in meta["customer"]).strip("-") or "assessment"
        col1, col2 = st.columns(2)
        col1.download_button(
            "Download Word report",
            data=docx_bytes,
            file_name=f"{safe_customer}-external-exposure-pqc-report.docx",
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            width="stretch",
        )
        col2.download_button(
            "Download Excel evidence",
            data=excel_bytes,
            file_name=f"{safe_customer}-external-exposure-pqc-evidence.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            width="stretch",
        )
        st.markdown("#### Report contents")
        st.write("Executive snapshot, prioritized findings, external asset inventory, vulnerability observations, TLS/PQC posture, interpretation limits, and source health.")


inject_styles()
if "engagement_input" not in st.session_state:
    st.session_state["engagement_input"] = "External exposure and PQC readiness review"

with st.sidebar:
    st.markdown("## Assessment profile")
    profile = st.radio(
        "Choose assessment depth",
        PROFILE_ORDER,
        key="assessment_profile",
        captions=["Recommended", "Fast first round", "Guided second round", "Expert controls"],
    )
    st.markdown(f"<div class='profile-note'>{html.escape(PROFILE_HELP[profile])}</div>", unsafe_allow_html=True)
    if profile == PROFILE_FOCUSED:
        st.text_input(
            "Additional TLS ports",
            key="extra_tls_ports_input",
            placeholder="Auto-filled after discovery",
            help="Port 443 is always assessed. Add only ports approved for this engagement.",
        )
    elif profile == PROFILE_CUSTOM:
        with st.expander("Advanced controls", expanded=True):
            st.checkbox("Assess TLS endpoints", value=True, key="custom_do_tls")
            st.checkbox(
                "Probe hybrid PQC key exchange",
                value=True,
                key="custom_probe_kex",
                help="Requires OpenSSL 3.5+. Otherwise the result remains UNKNOWN.",
            )
            st.slider("TLS timeout (seconds)", 3, 20, 8, key="custom_tls_timeout")
            st.slider("Parallel TLS checks", 1, 20, 8, key="custom_tls_workers")
            st.text_input("Additional direct-TLS ports", key="custom_extra_ports", placeholder="8443, 9443")
    do_tls, probe_kex, tls_timeout, tls_workers, extra_ports = profile_parameters(profile)
    st.divider()
    if do_tls and probe_kex:
        if pqc_tls.openssl_supports_mlkem():
            st.success("Hybrid key-exchange probing available")
        else:
            st.warning("Hybrid key-exchange probing unavailable; KEX will remain UNKNOWN")
    elif not do_tls:
        st.info("TLS checks are deferred to the follow-up round")
    st.caption(
        f"Safety limits: {recon_core.MAX_INPUT_TARGETS} inputs, {recon_core.MAX_DISCOVERED_IPS} public IPs, "
        f"{recon_core.MAX_TLS_ENDPOINTS} TLS endpoint combinations. Private and reserved addresses are blocked."
    )

st.markdown(
    """
    <div class="product-header">
      <div>
        <p class="section-kicker">Presales decision support</p>
        <h1>External Exposure &amp; PQC Readiness</h1>
        <p>Turn authorized public-domain reconnaissance into traceable observations, customer-validation questions, and a defensible evidence package.</p>
      </div>
      <span class="method-badge">V2.0 · Deterministic analysis</span>
    </div>
    """,
    unsafe_allow_html=True,
)

current_result = st.session_state.get("scan_result_v2")
st.markdown(workflow_steps(bool(current_result)), unsafe_allow_html=True)
if st.session_state.pop("followup_prepared", False):
    st.info("Focused follow-up is prepared. Review the auto-filled scope and ports, then confirm authorization again.")

with st.container(border=True):
    st.markdown("### Engagement setup")
    customer_col, engagement_col = st.columns(2)
    customer = customer_col.text_input("Customer / account alias", key="customer_input", placeholder="Use a sanitized name for demonstrations")
    engagement = engagement_col.text_input("Engagement", key="engagement_input")
    scope = st.text_input("Scope note", key="scope_input", placeholder="Approved domains, business boundary, or assessment purpose")
    target_text = st.text_area(
        "Authorized public domains or IP addresses",
        key="targets_input",
        height=135,
        placeholder="example.com\nwww.example.com",
        help=f"One target per line. Maximum {recon_core.MAX_INPUT_TARGETS}. URLs are normalized to hostnames.",
    )
    authorized = st.checkbox("I confirm these public targets are authorized for defensive assessment.", key="authorized_input")
    run_col, demo_col = st.columns(2)
    run_clicked = run_col.button("Run assessment", type="primary", disabled=not authorized, width="stretch")
    demo_clicked = demo_col.button("Load sanitized demo", width="stretch")

if demo_clicked:
    st.session_state["scan_result_v2"] = demo_data.build_demo_result()
    st.rerun()

if run_clicked:
    completed_result = run_scan(
        customer,
        engagement,
        scope,
        target_text,
        do_tls,
        probe_kex,
        tls_timeout,
        tls_workers,
        extra_ports,
        profile,
    )
    if completed_result:
        st.session_state["scan_result_v2"] = completed_result
        st.rerun()

result = st.session_state.get("scan_result_v2")
if result:
    st.divider()
    display_results(result)
else:
    st.markdown(
        "<div class='boundary-note'><strong>Designed for presales discovery:</strong> results are framed as evidence-backed observations and validation questions, not confirmed vulnerabilities or automatic product recommendations.</div>",
        unsafe_allow_html=True,
    )
