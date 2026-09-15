# External Exposure & PQC Readiness V2

Presales-oriented Streamlit application for authorized external reconnaissance, vulnerability enrichment, TLS certificate lifecycle review, and post-quantum readiness assessment.

The original `PQC` folder is unchanged. This V2 is a separate deployment candidate.

## What Changed

- Public-target validation blocks private, loopback, link-local, multicast, and reserved addresses.
- Per-run input, discovered-IP, CVE-enrichment, port, and TLS-endpoint limits.
- Multiple hostnames and SNI relationships are retained for each IP.
- External-source failures are visible instead of silently becoming empty results.
- Shodan InternetDB CVE associations are enriched with CISA KEV and FIRST EPSS.
- Findings are framed as observations, confidence, customer questions, and next actions.
- TLS lifecycle and PQC/key-exchange conclusions remain separate.
- CA/B applicability and NIST IR 8547 draft status are explicitly qualified.
- Deterministic Word report and formatted Excel evidence package.
- Built-in sanitized demonstration mode that performs no network scanning.

## Local Run

```powershell
python -m pip install -r requirements.txt
streamlit run app.py
```

## Streamlit Community Cloud

Deploy `app.py` as the entry point and add these optional secrets in the app settings:

```toml
dnsdumpster_api_key = "..."
opencve_user = "..."
opencve_pass = "..."
```

The app still runs without DNSDumpster or OpenCVE credentials. Their source-health status will show `Not configured`; Google DNS, Shodan InternetDB, CISA KEV, FIRST EPSS, and TLS checks remain available.

OpenSSL 3.5+ is optional. Without it, certificate assessment still works and hybrid key-exchange results remain `UNKNOWN` rather than being guessed.

## Verification

```powershell
python -m unittest discover -s tests -v
python -m py_compile app.py data_sources.py pqc_tls.py recon_core.py reporting.py
```

## Interpretation Boundary

This is a defensive discovery and presales-validation tool. External telemetry does not prove ownership, exact product version, exploitability, business impact, or absence of vulnerabilities. Confirm observations with the customer and authenticated evidence before making remediation or solution decisions.
