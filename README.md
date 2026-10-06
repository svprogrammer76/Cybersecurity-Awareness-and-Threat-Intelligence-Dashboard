# Cybersecurity Awareness & Threat Intelligence Dashboard

## Overview
A local, defensive learning dashboard joining a generated synthetic threat feed, IOC syntax checks, risk/context summaries, basic correlation, alerts, vulnerability awareness, and security awareness training. It uses the beginner stack: Python, Flask, SQLite, HTML/CSS/JavaScript. All threat observations are explicitly fictional; no external feeds or services are contacted.

## Problem statement and objectives
Security teams need a way to turn technical observations into contextual decisions while helping people avoid common risks. This project demonstrates that workflow with reproducible demo records. It is an educational prototype, not a production SIEM or a source of live threat intelligence.

## Architecture
`Synthetic CSV → local Flask API → SQLite → local search/enrichment/alert services → browser dashboard`; a parallel awareness module and quiz provide user education. The REST API is read-only for threat data except local analyst notes, alert status, and quiz submissions.

## Features
- 2,002 reproducible synthetic observations (2,000 generated rows plus the two fixed walkthrough examples) using documentation IP ranges and reserved example domains, generated with seed 2026.
- Local IOC format validator for IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256-shaped hashes, and CVE IDs. Syntax validity does not mean maliciousness or that a CVE exists.
- Search, filters, severity/confidence and risk display, record details, synthetic timeline, campaign-cluster hints, and local notes.
- Risk scoring with severity, confidence, recency, frequency, source reliability, alert and context factors; confidence remains a separate field.
- Synthetic security alerts, local vulnerability awareness, a 15-topic learning center, and a 32-question quiz.
- SQLite persistence and JSON REST endpoints.

## Threat intelligence concepts
Strategic intelligence guides long-range decisions; operational intelligence describes campaigns and intent; tactical intelligence describes procedures and behaviors; technical intelligence includes indicators such as domains and hashes. IOCs are observable artifacts; IOAs describe behavior. A threat feed is a set of collected observations. Enrichment adds context, while correlation groups records with a shared demo campaign label. Correlation does not prove attribution.

An observation is a recorded event or data point. An indicator is an artifact to investigate. An alert is a rule-triggered prompt for review. A threat is a potential source or circumstance of harm. An incident is an event assessed as affecting confidentiality, integrity, or availability. This application does not assert incidents from indicator matches.

## Risk and confidence
Risk is a 0–100 prioritization estimate based on the documented weighted components in `backend/services/risk_engine.py`. Confidence is the feed's evidence-quality score. High risk with low confidence means potentially important but weakly supported. A high score never confirms compromise.

## ATT&CK and vulnerabilities
A small illustrative mapping is assigned to selected synthetic phishing records only. ATT&CK tactics describe why an action occurs; techniques describe how a behavior is performed. The demo does not claim validated actor behavior. CVE-shaped synthetic records are not real vulnerability advisories or current CVSS evaluations.

## Run locally
Requires Python 3.10+.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m data.generate_threat_data
python -c "from backend.app import init_db; init_db()"
python -m backend.app
```
Open `http://127.0.0.1:5000`. Search `198.51.100.25` or any generated sample. Browse a row for details, then use Awareness Center and complete the quiz. The server binds only to localhost. For PowerShell policy restrictions, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current shell only.

## API
- `GET /api/health`, `/api/stats`, `/api/threats`, `/api/threats/<id>`
- `GET /api/search?indicator=...`, `/api/enrich?indicator=...`
- `GET /api/vulnerabilities`, `/api/alerts`; `PATCH /api/alerts/<id>` with `{"status":"INVESTIGATING"}`
- `POST /api/threats/<id>/notes` with `{"note":"..."}`
- `GET /api/awareness/modules`, `/api/quiz`; `POST /api/quiz/submit` with an `answers` array

Responses are JSON. Invalid query arguments return 400, missing threats 404, successful note insertions 201. This local student demo does not implement user authentication/RBAC, HTTPS termination, or distributed rate limiting; keep it bound to localhost and do not expose it as a service.

## Testing
Run `python -m unittest discover -s tests -v` for 35+ validator, scoring, API, persistence, training, alert and search checks.

## Security and privacy
No submitted indicator is fetched, resolved, scanned, or executed. Input is length bounded on notes and displayed in the browser using HTML escaping. Keep real intelligence and analyst notes out of public demos. Production deployment would require authentication and RBAC, audit logging, CSRF protection, secure secret storage, HTTPS, rate limiting, retention controls, and organization-approved feeds.

## Limitations and future improvements
No live intel, real CVE verification, production ATT&CK data, actor attribution, user accounts, or incident confirmation is included. Future defensive work could add authorized STIX/TAXII feeds, feed expiry/deduplication, validated CVE/KEV/EPSS context, SIEM/SOAR integration, RBAC, audit history, Docker and CI/CD after threat modeling and review.

## Learning outcomes and roles
This prototype practices data validation, Python API development, SQLite persistence, basic threat prioritization, alert review, awareness content, and safe demo design—skills relevant to SOC, cyber analysis, CTI, incident response, vulnerability analysis, and security engineering. A SOC monitors and triages; analysts assess evidence; CTI analysts contextualize reporting; incident responders coordinate containment and recovery; hunters investigate hypotheses; awareness specialists build safer habits.

## Ethical disclaimer
This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.

