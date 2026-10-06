SEVERITY = {"INFORMATIONAL": 10, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
SOURCE_RELIABILITY = {"Internal SOC": 90, "Security Vendor": 85, "Public Threat Feed": 70, "Research Report": 75, "Community Submission": 55, "Unknown Source": 30}
def calculate_threat_risk(severity, confidence, recency=70, observations=1, source_reliability=60, related_alerts=0, context=50):
    factors=[SEVERITY.get(str(severity).upper(),10), confidence, recency, min(100,observations*10), source_reliability, min(100,related_alerts*25), context]
    return round(sum(x*w for x,w in zip(factors,[.30,.25,.15,.10,.10,.05,.05])))
def classify_risk(score):
    return "INFORMATIONAL" if score<=20 else "LOW" if score<=40 else "MEDIUM" if score<=60 else "HIGH" if score<=80 else "CRITICAL"
