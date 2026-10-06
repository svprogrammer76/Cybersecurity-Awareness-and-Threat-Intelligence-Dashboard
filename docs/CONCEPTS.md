# Beginner concept and workflow guide

## Plain-language glossary
- **Cybersecurity awareness:** practical habits that help people recognize and report risk.
- **Threat intelligence:** analyzed information used to support defensive decisions.
- **IOC:** observable artifact such as an IP, domain, URL, hash, sender domain or vulnerability identifier. IOCs can be stale or benign; a match does not prove compromise.
- **IOA:** behavior that may indicate an attack, interpreted with context.
- **Vulnerability:** a weakness that could affect a system. **CVE** is a standardized identifier; **CVSS** is a vulnerability severity scoring framework.
- **Threat feed:** collected observations from one or more sources.
- **Threat actor:** a person or group believed to conduct activity; attribution needs substantial evidence.
- **TTP:** tactics, techniques and procedures: objectives, behaviors, and recurring methods.
- **MITRE ATT&CK:** a knowledge base organizing observed adversary behaviors. Tactic is the goal, technique is the behavior used to pursue it, and sub-technique is a more specific variant.
- **Enrichment:** attaching useful context to an observation. **Correlation:** linking records based on shared evidence; this is not attribution.
- **Threat hunting:** proactive, hypothesis-led review of authorized telemetry.
- **SOC:** Security Operations Center; people and processes that monitor, triage, investigate, and coordinate response.

## Awareness and intelligence together
Awareness trains human defenses: phishing recognition, password and MFA habits, safe browsing, social engineering resistance, software updates, Wi-Fi, privacy, and reporting. Threat intelligence supports technical defense through structured observations, context, and prioritization. The project joins these to teach both what analysts review and what users can do.

## Intelligence levels
Strategic: long-term trends to inform leadership. Operational: campaign context and objectives. Tactical: behaviors and methods. Technical: indicators and machine-readable observations. This prototype focuses on technical/tactical concepts and awareness.

## Industry relevance and roles
SOCs, banks, cloud providers, enterprises, government, e-commerce, healthcare, universities, MSSPs and consultancies use these practices to prioritize defensive work. SOC analysts triage; cyber analysts investigate; CTI analysts assess reporting; incident responders coordinate response; security engineers build controls; vulnerability analysts prioritize remediation; awareness specialists teach safer behavior; threat hunters test hypotheses against authorized telemetry. This project practices introductory data validation, APIs, scoring, filtering, safe triage, and user education.

## Workflow
Synthetic CSV → collection → normalization → syntax validation → classification → contextual enrichment → separate risk and confidence → database → evidence-based correlation → alert review → analyst/user dashboard → awareness training. The lifecycle for an IOC is observed → validated → enriched → scored → investigated → monitored → expired/closed. Validate means syntax here, never maliciousness.

## Source reliability versus confidence
Source reliability is an overall estimate of a publisher's consistency; confidence is how well supported a specific record is. A reliable source can submit a low-confidence item, and an unknown source can provide a verifiable observation. Both are distinct from risk, which estimates possible concern/priority.

## Safe incident awareness
Record what happened and when, preserve relevant messages/logs according to organizational policy, and promptly use the organization's reporting channel. Do not click, forward suspicious links broadly, confront a suspected actor, or delete evidence. Follow the response team's instructions.

## Expected limits
Cloud IPs/domains may be shared, reassigned, or benign. Feeds disagree and data ages. Correlation cannot establish actor identity or compromise. This tool is a local classroom prototype, not a production service.
