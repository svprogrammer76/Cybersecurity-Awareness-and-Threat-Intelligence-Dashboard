from __future__ import annotations
import ipaddress, re
from urllib.parse import urlsplit

_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}

def validate_indicator(value: str) -> dict:
    """Check syntax only; this does not determine reputation or maliciousness."""
    raw = (value or "").strip()
    if not raw: return {"valid": False, "indicator_type": None, "normalized_value": "", "validation_notes": "Empty input."}
    try:
        ip = ipaddress.ip_address(raw)
        return {"valid": True, "indicator_type": "IP", "normalized_value": ip.compressed, "validation_notes": "Syntactically valid IP; not a reputation assessment."}
    except ValueError: pass
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", raw, re.I):
        return {"valid": True, "indicator_type": "CVE", "normalized_value": raw.upper(), "validation_notes": "CVE identifier format only; existence is not verified."}
    if re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", raw):
        return {"valid": True, "indicator_type": "FILE_HASH", "normalized_value": raw.lower(), "validation_notes": "Hash-length format only; file is never accessed."}
    if re.match(r"^https?://", raw, re.I):
        try:
            u=urlsplit(raw)
            if u.hostname and not any(c.isspace() for c in raw):
                return {"valid": True, "indicator_type": "URL", "normalized_value": raw, "validation_notes": "URL syntax checked locally; URL was not contacted."}
        except ValueError: pass
        return {"valid": False, "indicator_type": "URL", "normalized_value": raw, "validation_notes": "Malformed URL."}
    domain=raw.rstrip(".").lower()
    if len(domain)<=253 and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",domain):
        return {"valid": True, "indicator_type": "DOMAIN", "normalized_value": domain, "validation_notes": "Domain syntax only; no DNS lookup performed."}
    return {"valid": False, "indicator_type": None, "normalized_value": raw, "validation_notes": "Unsupported or invalid indicator syntax."}
