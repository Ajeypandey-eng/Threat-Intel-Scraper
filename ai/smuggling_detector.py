import re
from typing import Dict, Any

def extract_clean_domain_str(raw_input: str) -> str:
    """
    Extracts the clean, normalized domain/host from a raw input string.
    Handles standard protocols, defanged markers (hxxp/ttp), ports, paths, and user credentials.
    """
    raw = (raw_input or "").strip().lower()
    # Strip protocols including defanged (http, https, ftp, ftps, hxxp, hxxps, ttp, ttps)
    raw = re.sub(r'^(?:hxxp|ttp|http|ftp)s?[:/]+', '', raw)
    # Strip path, query params, anchor
    raw = raw.split('/')[0].split('?')[0].split('#')[0]
    if '@' in raw:
        raw = raw.split('@')[-1]
    if ':' in raw:
        raw = raw.split(':')[0]
    raw = raw.strip('. ')
    return raw if raw else (raw_input or "").strip()

def detect_url_smuggling(raw_input: str) -> Dict[str, Any]:
    """
    Detects adversarial concatenated URL smuggling and domain framing attacks.
    Protects both major backbones AND minor victim domains (e.g. smallbakery.com, college.edu, localgym.org)
    from being framed and maliciously reported to public blocklists.

    Broadcasts whenever two or more protocol schemes (http, https, ftp, ftps, sftp, hxxp, ttp)
    are chained in the input.

    Examples:
      - 'smallbakery.comhttp://114.239.63.214:39292/i'
      - 'https://smallbakery.comftp://malware.com'
      - 'http://victim.orghttps://phish.xyz'
      - 'college.eduftps://badactor.net'
      - 'ftps://school.eduhttp://114.239.63.214:39292/i'
      - 'innocent.com@185.220.101.5:8080'
    """
    raw = (raw_input or '').strip()
    
    # 1. Scheme markers (http, https, ftp, ftps, sftp, hxxp, hxxps, ttp, ttps)
    scheme_matches = list(re.finditer(r'(https?|ftps?|sftp|hxxps?|ttps?)[:/]+', raw, re.IGNORECASE))
    
    is_smuggled = False
    prefix_raw = raw
    payload_raw = raw
    schemes_found = []
    technique = None

    # Case A: Two or more scheme indicators (e.g. 'http://victim.comhttps://evil.com' or 'https://smallbakery.comftp://malware.com')
    if len(scheme_matches) >= 2:
        is_smuggled = True
        second_match = scheme_matches[1]
        prefix_raw = raw[:second_match.start()].strip()
        payload_raw = raw[second_match.start():].strip()
        schemes_found = [m.group(1).lower() for m in scheme_matches]
        technique = "Multi-Scheme Protocol Concatenation"
        
    # Case B: Exactly 1 scheme indicator, but appearing after leading domain/text (e.g. 'smallbakery.comhttp://evil.com')
    elif len(scheme_matches) == 1:
        match = scheme_matches[0]
        if match.start() > 0:
            candidate_prefix = raw[:match.start()].strip()
            # If candidate prefix contains a dot, slash, or host marker, it represents a lure domain
            if '.' in candidate_prefix or '/' in candidate_prefix:
                is_smuggled = True
                prefix_raw = candidate_prefix
                payload_raw = raw[match.start():].strip()
                schemes_found = [match.group(1).lower()]
                technique = "Embedded Protocol Lure Smuggling"

    # Case C: User-info '@' delimiter smuggling (e.g. 'innocent.org@185.220.101.5')
    if not is_smuggled and '@' in raw:
        parts = raw.split('@')
        if len(parts) == 2 and '.' in parts[0] and ('.' in parts[1] or ':' in parts[1]):
            is_smuggled = True
            prefix_raw = parts[0].strip()
            payload_raw = parts[1].strip()
            schemes_found = ["auth_delimiter_smuggle"]
            technique = "Credential / Userinfo Delimiter Smuggling"

    # Clean domain extractions
    lure_prefix_domain = extract_clean_domain_str(prefix_raw) if is_smuggled else None
    active_payload_domain = extract_clean_domain_str(payload_raw)
    is_multi_protocol = len(schemes_found) >= 2

    warning = None
    broadcast_alert = None
    if is_smuggled:
        scheme_tag = " + ".join([s.upper() for s in schemes_found]) if schemes_found else "CONCAT"
        broadcast_alert = (
            f"PROTOCOL SMUGGLING BROADCAST: Detected {scheme_tag} scheme chaining. "
            f"Innocent lure domain '{lure_prefix_domain}' has been granted Universal Immunity. "
            f"Active threat payload '{active_payload_domain}' isolated for inspection."
        )
        warning = (
            f"Adversarial URL smuggling detected ({technique}). Innocent lure domain '{lure_prefix_domain}' "
            f"(minor or major domain) was concatenated with active payload '{active_payload_domain}'. "
            f"The innocent lure domain is granted Universal Immunity against public blocklist reporting, "
            f"and threat intelligence has isolated the destination payload for inspection."
        )

    return {
        "is_concatenated": is_smuggled,
        "is_multi_protocol": is_multi_protocol,
        "technique": technique,
        "schemes_found": schemes_found,
        "lure_prefix_raw": prefix_raw if is_smuggled else None,
        "lure_prefix_domain": lure_prefix_domain,
        "active_payload_raw": payload_raw,
        "active_payload_domain": active_payload_domain,
        "immunity_tier": "Universal Immunity (Minor & Major Domains Shielded)",
        "broadcast_alert": broadcast_alert,
        "warning": warning
    }
