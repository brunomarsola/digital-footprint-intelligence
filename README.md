# Digital Footprint Intelligence

```text
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│             DIGITAL FOOTPRINT INTELLIGENCE                   │
│                                                              │
│       COLLECT  →  CORRELATE  →  ANALYZE  →  INTELLIGENCE    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

> Passive digital footprint collection, infrastructure correlation and intelligence analysis for Cyber Threat Intelligence investigations.

---

## Overview

**Digital Footprint Intelligence** is a Python-based passive intelligence collection and analysis tool designed to identify, normalize, correlate and analyze publicly observable infrastructure associated with a target domain.

The project is focused on **Cyber Threat Intelligence (CTI)**, digital footprint analysis and infrastructure investigation.

Rather than treating collected information as isolated observations, the project builds a structured infrastructure model and derives relationships, risk findings and similarity signals from the collected data.

### Investigation Pipeline

```text
                         ┌───────────────┐
                         │    TARGET     │
                         └───────┬───────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
               DNS              RDAP              CT
                │                │                │
                └────────────────┼────────────────┘
                                 │
                         ┌───────▼───────┐
                         │  NORMALIZE    │
                         └───────┬───────┘
                                 │
                         ┌───────▼───────┐
                         │    ANALYSIS   │
                         └───────┬───────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
             RISK          RELATIONSHIPS      SIMILARITY
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                         ┌───────▼───────┐
                         │ INTELLIGENCE  │
                         └───────┬───────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                   TXT           MD       CSV / JSON
```

---

## Objectives

The main objectives of the project are:

- Collect passive intelligence from multiple public sources.
- Normalize heterogeneous infrastructure data.
- Model domains, IP addresses and certificates as structured entities.
- Identify relationships between infrastructure components.
- Classify certificate-related intelligence.
- Detect infrastructure risk signals.
- Correlate infrastructure similarity signals.
- Preserve collection failures and uncertainty.
- Export investigation results for further analysis or integration.

The project is designed around the principle that **missing data should not automatically be interpreted as evidence that infrastructure does not exist**.

---

# Features

## Passive Collection

### DNS

The DNS collector currently handles:

- A records
- AAAA records
- MX records
- NS records
- TXT records
- CNAME records

The collector also handles DNS conditions such as:

- NXDOMAIN
- NoAnswer
- NoNameservers
- DNS timeout
- Null MX records

---

### Certificate Transparency

Certificate Transparency data is collected through `crt.sh`.

The collector:

- Queries Certificate Transparency records.
- Extracts certificate records.
- Extracts DNS names from certificate data.
- Normalizes discovered names.
- Filters invalid DNS values.
- Retries transient upstream failures.
- Records collection attempts and errors.

Transient HTTP failures currently covered by retry logic include:

```text
502
503
504
```

If a collection source fails, the investigation continues and the failure is preserved in the collection status.

---

### RDAP

RDAP information is used to enrich infrastructure intelligence with publicly available registration information.

The collector handles information such as:

- Nameservers
- Registration events
- Domain-related metadata

---

# Intelligence Analysis

## Certificate Intelligence

Certificates are classified according to their relationship with the investigated target.

Current classifications:

```text
VALID_DOMAIN
WILDCARD
EXTERNAL_DOMAIN
NON_DOMAIN
```

Example:

```text
example.com
    └── VALID_DOMAIN

*.example.com
    └── WILDCARD

www.example.org
    └── EXTERNAL_DOMAIN

user@example.com
    └── NON_DOMAIN
```

Certificate names are not automatically treated as confirmed infrastructure.

For example, a wildcard certificate entry may provide useful intelligence without representing a directly observed infrastructure entity.

---

## Relationship Analysis

The Relationship Engine derives relationships between infrastructure entities.

Current relationship types include:

```text
RESOLVES_TO
SUBDOMAIN_OF
HAS_CERTIFICATE
CERTIFICATE_FOR
SHARES_IP
SHARES_CERTIFICATE
CNAME_TO
USES_NAMESERVER
USES_MAIL_SERVER
RELATED_TO
```

Example:

```text
example.com
    │
    ├── RESOLVES_TO ────────> 104.20.23.154
    │
    ├── RESOLVES_TO ────────> 172.66.147.243
    │
    ├── USES_NAMESERVER ────> ns.example.net
    │
    └── HAS_CERTIFICATE ────> certificate-id
```

Relationships include:

- Source
- Target
- Relationship type
- Confidence
- Evidence

The engine also performs relationship deduplication.

---

## Risk Analysis

The Risk Engine evaluates collected intelligence and generates structured findings.

Findings contain:

- Rule ID
- Severity
- Title
- Description
- Evidence
- Confidence

The system currently handles signals such as:

- Multiple discovered IP addresses
- Expanded domain footprint
- Collection failures
- Certificate-related intelligence

---

## Similarity Analysis

The project contains a similarity analysis layer capable of correlating relationships into similarity signals.

Current similarity concepts include:

```text
SHARED_IP
SHARED_CERTIFICATE
SHARED_NAMESERVER
SHARED_MAIL_SERVER
SHARED_CNAME
SUBDOMAIN_RELATION
```

Multiple signals can be correlated for the same infrastructure pair.

The advanced similarity scoring and clustering functionality is part of the project roadmap.

---

# Architecture

The project follows a layered architecture.

```text
                    ┌──────────────────────┐
                    │         CLI          │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Investigation      │
                    │       Service        │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
        │ Collectors│    │   Models   │    │  Analysis │
        └─────┬─────┘    └───────────┘    └─────┬─────┘
              │                                  │
       ┌──────┼──────┐              ┌────────────┼────────────┐
       │      │      │              │            │            │
      DNS    RDAP    CT             Risk     Relationships Similarity
       │      │      │
       └──────┼──────┘
              │
              ▼
       Infrastructure
           Aggregate
              │
              ▼
          Exporters
       ┌──────┼──────┬──────┐
       │      │      │      │
      TXT     MD     CSV    JSON
```

---

# Project Structure

```text
digital-footprint-intelligence/
│
├── app/
│   ├── analysis/
│   │   ├── certificate.py
│   │   ├── certificate_rules.py
│   │   ├── infrastructure.py
│   │   ├── relationship.py
│   │   ├── risk.py
│   │   └── similarity.py
│   │
│   ├── collectors/
│   │   ├── crtsh.py
│   │   ├── dns.py
│   │   └── rdap.py
│   │
│   ├── enrichment/
│   │   ├── certificate.py
│   │   ├── domain.py
│   │   └── ip.py
│   │
│   ├── exporters/
│   │   ├── csv.py
│   │   ├── json.py
│   │   ├── markdown.py
│   │   └── txt.py
│   │
│   ├── models/
│   │   ├── certificate.py
│   │   ├── collection.py
│   │   ├── domain.py
│   │   ├── finding.py
│   │   ├── infrastructure.py
│   │   ├── ip.py
│   │   ├── relationship.py
│   │   └── similarity.py
│   │
│   ├── output/
│   │   └── writer.py
│   │
│   ├── services/
│   │   └── investigation.py
│   │
│   └── cli.py
│
├── tests/
│
├── output/
│
├── README.md
└── ...
```

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
cd digital-footprint-intelligence
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

Run a basic investigation:

```bash
python -m app.cli example.com
```

The CLI displays:

- Infrastructure summary
- Collection status
- Risk findings
- Domains
- IP addresses
- Relationships
- Certificate intelligence

---

## Saving Results

Results can be saved using:

```bash
python -m app.cli example.com --save --txt
```

Markdown:

```bash
python -m app.cli example.com --save --md
```

CSV:

```bash
python -m app.cli example.com --save --csv
```

JSON:

```bash
python -m app.cli example.com --save --json
```

Multiple formats can be requested together:

```bash
python -m app.cli example.com --save --json --md --txt --csv
```

---

# Output

Investigation results are stored in timestamped directories.

Example:

```text
output/
└── example.com/
    └── 2026-10-01_211500/
        ├── report.json
        ├── report.txt
        ├── report.md
        ├── collection_status.csv
        ├── domains.csv
        ├── ips.csv
        ├── certificates.csv
        ├── findings.csv
        ├── relationships.csv
        └── similarity.csv
```

JSON is intended to provide a structured interface for future integrations.

---

# Example Investigation

Example target:

```text
example.com
```

A successful investigation can produce information such as:

```text
Domains discovered:     7
IP addresses:           4
Certificates:           81
Relationships:          ...
```

Example relationships:

```text
example.com
  - RESOLVES_TO -> 104.20.23.154
    Confidence: HIGH
    Evidence: DNS A record

example.com
  - USES_NAMESERVER -> ns.example.net
    Confidence: HIGH
    Evidence: DNS NS record
```

Certificate intelligence may identify:

```text
VALID_DOMAIN
WILDCARD
EXTERNAL_DOMAIN
NON_DOMAIN
```

The exact results depend on the target and the availability of external intelligence sources at the time of investigation.

---

# Collection Failures

External intelligence sources may become unavailable or return temporary errors.

For example:

```text
crt.sh      ERROR       3 attempt(s)
  Error: HTTP 502: temporary upstream failure
```

The investigation does not interpret this as:

```text
"No certificates exist."
```

Instead, it records the collection failure:

```text
COLLECTION-001
Incomplete collection
```

This distinction is important for intelligence analysis because:

```text
No observation
      ≠
Evidence of absence
```

The tool is designed to continue collecting from available sources when one source fails.

---

# Security and Privacy Considerations

Digital Footprint Intelligence is designed primarily around **passive collection**.

Passive collection does not guarantee anonymity or prevent external services from logging requests.

Users should consider:

- Network visibility
- DNS resolver logging
- HTTP request logging
- Third-party service policies
- Rate limiting
- Operational security requirements
- Handling of collected intelligence
- Storage of investigation results

The tool should be used only for authorized investigations and legitimate security research.

---

# Limitations

Current limitations include:

- External data sources may become unavailable.
- Certificate Transparency data depends on public CT infrastructure.
- DNS results represent observations at collection time.
- Passive collection does not guarantee complete infrastructure discovery.
- External domains appearing in certificates are treated as intelligence evidence rather than automatically confirmed infrastructure.
- No anonymity guarantee is provided.
- Historical infrastructure tracking is not yet implemented.
- Advanced infrastructure clustering is still under development.
- Multi-target investigations are still under development.

---

# Testing

The project uses `pytest`.

Run the complete test suite:

```bash
python -m pytest -vv
```

Current test status:

```text
146 passed
```

The test suite covers:

- Models
- Collectors
- Certificate classification
- Certificate rules
- Risk analysis
- Relationship analysis
- Similarity analysis
- Investigation service
- CLI
- Exporters
- Output management

---

# Roadmap

## 🟢 Sprint 1 — v1.0

- [x] CLI
- [x] `--save / -S`
- [x] TXT exporter
- [x] Markdown exporter
- [x] CSV exporter
- [x] JSON exporter
- [x] Organized output directories
- [ ] Multiple targets
- [x] Exporter tests
- [x] CLI tests

---

## 🟢 Sprint 2 — Documentation

- [ ] README
- [ ] Architecture documentation
- [ ] Usage documentation
- [ ] Example investigation
- [ ] Limitations
- [ ] Security / privacy considerations
- [ ] Roadmap documentation

---

## 🟡 Sprint 3 — Advanced Intelligence

- [ ] Similarity Score
- [ ] Infrastructure Clusters
- [ ] Entity Prioritization
- [ ] Attack Surface Summary
- [ ] Risk Correlation
- [ ] Graph Export

---

## 🔵 Future

- [ ] API
- [ ] SIEM integration
- [ ] SOC integration
- [ ] Dashboard
- [ ] Scheduled investigations
- [ ] Historical comparison
- [ ] Change detection

---

# Project Status

**Active Development**

The project currently focuses on building a reliable foundation for passive digital footprint collection, infrastructure modeling and CTI analysis.

The architecture is intentionally being developed incrementally, with tests covering the behavior of each major component before expanding the analytical capabilities.

---

# Disclaimer

This project is intended for authorized security research, Cyber Threat Intelligence investigations, defensive security operations and educational purposes.

Always obtain appropriate authorization before investigating infrastructure that you do not own or have permission to assess.

---

# License

Add the project license here.
