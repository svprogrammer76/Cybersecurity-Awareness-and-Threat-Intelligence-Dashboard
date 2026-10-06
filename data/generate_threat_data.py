import csv, random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from backend.services.risk_engine import calculate_threat_risk
CATEGORIES=["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL THREATS","WEB THREATS","NETWORK THREATS","VULNERABILITY EXPOSURE","SOCIAL ENGINEERING","DATA EXPOSURE","ACCOUNT SECURITY"]
TYPES=["IP","DOMAIN","URL","FILE_HASH","EMAIL/SENDER DOMAIN","CVE ID"]
SOURCES=["Internal SOC","Security Vendor","Public Threat Feed","Research Report","Community Submission","Unknown Source"]
STATUSES=["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"]
def generate(path="data/threat_intelligence_dataset.csv", count=2000, seed=2026):
    rng=random.Random(seed); now=datetime(2026,10,6,tzinfo=timezone.utc); out=Path(path); out.parent.mkdir(parents=True,exist_ok=True)
    fields="threat_id timestamp threat_name threat_category indicator_type indicator_value source_name confidence_score severity risk_score status first_seen last_seen country_or_region_optional description mitre_tactic_optional mitre_technique_optional cve_id_optional dataset_label observation_count campaign_id source_reliability".split()
    with out.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for i in range(1,count+1):
            cat=CATEGORIES[(i-1)%len(CATEGORIES)]; typ=TYPES[(i-1)%len(TYPES)]; seen=now-timedelta(days=rng.randrange(0,365)); sev=rng.choices(list(["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"]),[5,20,35,30,10])[0]; conf=rng.randrange(35,100); src=rng.choice(SOURCES)
            value={"IP":f"198.51.100.{(lambda n: n if n < 25 else n + 1)(rng.randrange(1,254))}","DOMAIN":f"demo-{rng.randrange(1,800)}.example.com","URL":f"https://example.com/demo/{i}","FILE_HASH":f"{rng.getrandbits(256):064x}","EMAIL/SENDER DOMAIN":f"sender-{rng.randrange(1,300)}.example.org","CVE ID":f"CVE-{2020+rng.randrange(7)}-{1000+rng.randrange(90000)}"}[typ]
            risk=calculate_threat_risk(sev,conf, max(5,100-(now-seen).days//4),rng.randrange(1,8),{k:v for k,v in [(s,x) for s,x in zip(SOURCES,[90,85,70,75,55,30])]}[src])
            w.writerow(dict(threat_id=f"THR-{2026}-{i:04d}",timestamp=seen.isoformat(),threat_name=f"Synthetic {cat.title()} Observation {i}",threat_category=cat,indicator_type=typ,indicator_value=value,source_name=src,confidence_score=conf,severity=sev,risk_score=risk,status=rng.choice(STATUSES),first_seen=seen.date().isoformat(),last_seen=(seen+timedelta(days=rng.randrange(0,15))).date().isoformat(),country_or_region_optional="DEMO",description="SYNTHETIC / DEMO ONLY. A training observation; not a confirmed attack.",mitre_tactic_optional="Initial Access" if cat in ("PHISHING","CREDENTIAL THREATS") else "",mitre_technique_optional="T1566" if cat=="PHISHING" else "",cve_id_optional=value if typ=="CVE ID" else "",dataset_label="SYNTHETIC / DEMO ONLY",observation_count=rng.randrange(1,8),campaign_id=f"CAMP-{i//3:04d}",source_reliability={"Internal SOC":90,"Security Vendor":85,"Public Threat Feed":70,"Research Report":75,"Community Submission":55,"Unknown Source":30}[src]))
    # Fixed, explicitly fictional walkthrough pair requested by the project brief.
    with out.open("a", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields)
        base=dict(timestamp="2026-10-06T00:00:00+00:00",threat_name="Synthetic Credential Phishing Campaign",threat_category="PHISHING",source_name="Research Report",confidence_score=85,severity="HIGH",risk_score=78,status="MONITORING",first_seen="2026-10-01",last_seen="2026-10-06",country_or_region_optional="DEMO",description="SYNTHETIC / DEMO ONLY. Indicator appears in multiple synthetic phishing observations.",mitre_tactic_optional="Initial Access",mitre_technique_optional="T1566",cve_id_optional="",dataset_label="SYNTHETIC / DEMO ONLY",observation_count=3,campaign_id="CAMP-DEMO-001",source_reliability=75)
        w.writerow(dict(base,threat_id="THR-2026-001",indicator_type="DOMAIN",indicator_value="login-check.invalid"))
        w.writerow(dict(base,threat_id="THR-2026-002",threat_name="Synthetic Credential Phishing Related Indicator",indicator_type="IP",indicator_value="198.51.100.25"))
    return str(out)
if __name__=="__main__": print(f"Generated {generate()} (synthetic demo data)")


