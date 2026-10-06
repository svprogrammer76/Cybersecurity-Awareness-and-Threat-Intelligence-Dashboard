# Student Project Report

## Abstract
This project presents a defensive cybersecurity awareness and threat intelligence dashboard for learning. A reproducible 2,002-record synthetic dataset (2,000 generated records plus two fixed walkthrough examples) powers local IOC lookup, risk prioritization, alert triage, and awareness education without contacting indicators.

## Introduction and problem
Organizations need to combine technical observations with human security habits. A raw indicator is not enough to establish compromise, so analysts need context, confidence, and a safe review process.

## Objectives and concepts
The implementation covers synthetic feed ingestion, syntactic IOC validation, data persistence, separate risk and confidence scores, category and status filtering, local alert handling, campaign-based correlation hints, vulnerability awareness, awareness modules, and quiz feedback. An IOC is an observable artifact; an IOA represents behavior. A CVE is a public vulnerability identifier; CVSS describes standardized vulnerability severity. ATT&CK organizes observed adversary tactics and techniques. A SOC monitors and coordinates defensive investigation.

## Architecture and method
A deterministic Python generator writes a CSV with documentation-range IPs, example domains, synthetic hashes and CVE-shaped examples. Flask validates and serves local records; SQLite stores records and analyst notes; a browser interface presents dashboard metrics, filters and education. No IOC is fetched or resolved.

## Scoring and correlation
Risk combines severity, confidence, recency, frequency, source reliability, alert association and context as a 0–100 prioritization heuristic. Confidence expresses evidence quality independently. Correlation groups a synthetic campaign identifier and does not prove common ownership or attribution.

## Awareness and alerts
Fifteen concise learning topics present safer behaviors. A 32-question quiz gives a training score and generic recommendation. High/critical demo observations can generate review alerts. Alerts and indicators do not establish an incident.

## Testing and results
The included unittest suite checks indicator syntax, risk behavior, endpoints, filtering, scoring, data count, awareness content and alert validation. The dashboard displays the generated observations and offers local lookup and investigation views.

## Security, limitations and future work
The dataset is fictional. CVE-shaped rows are not verified vulnerabilities and sample ATT&CK mapping is illustrative. This is not a production SOC platform and lacks authentication, RBAC, audit controls and live feeds. A production system would require authorized feed provenance, expiration, access control, secure deployment, and validated vulnerability sources. Potential defensive extensions include STIX/TAXII, SIEM/SOAR, KEV awareness and auditable workflows.

## Conclusion
The project gives a beginner a runnable foundation for safe threat-intelligence literacy and cybersecurity awareness, with explicit uncertainty and non-interaction safeguards.

