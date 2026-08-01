from scraper.whois_lookup import get_whois_data
from scraper.dns_lookup import get_dns_records
from scraper.tls_lookup import get_tls_info
from scraper.http_headers import get_security_headers

# Risk points are DEDUCTED from 100 (max trust).
# The final score = 100 - total_deductions, clamped to [0, 100].
# A score of 100 = perfectly trusted. A score of 0 = maximum risk.

WEIGHTS = {
    "new_domain_severe":   40,   # < 30 days old
    "new_domain_moderate": 20,   # 30 – 180 days old
    "whois_unavailable":   10,   # Can't retrieve WHOIS at all
    "no_spf":              10,   # Missing SPF record
    "no_dmarc":            10,   # Missing DMARC record
    "no_https":            25,   # Invalid/missing TLS certificate
    "no_hsts":             10,   # Missing Strict-Transport-Security
    "no_csp":               5,   # Missing Content-Security-Policy (common even on legit sites)
}

def calculate_risk(domain: str):
    # Strip protocol prefixes if user accidentally passes them
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Strip paths
    domain = domain.split("/")[0].strip()

    whois_data   = get_whois_data(domain)
    dns_records  = get_dns_records(domain)
    tls_info     = get_tls_info(domain)
    headers_info = get_security_headers(domain)

    deductions = 0
    warnings   = []
    positives  = []

    # ── 1. WHOIS / Domain Age ────────────────────────────────────────────────
    age_days = whois_data.get("age_days")
    if age_days is None:
        if whois_data.get("error"):
            deductions += WEIGHTS["whois_unavailable"]
            warnings.append(
                f"WHOIS data unavailable — cannot verify domain age or registrar. "
                f"({whois_data.get('error', 'Unknown error')})"
            )
    elif age_days < 30:
        deductions += WEIGHTS["new_domain_severe"]
        warnings.append(
            f"⚠ Very new domain — only {age_days} day(s) old. "
            "Newly registered domains are a common indicator of phishing infrastructure."
        )
    elif age_days < 180:
        deductions += WEIGHTS["new_domain_moderate"]
        warnings.append(
            f"Domain is relatively young ({age_days} days old, <6 months). "
            "Treat with caution."
        )
    else:
        years = round(age_days / 365, 1)
        positives.append(f"✓ Established domain — {years} year(s) old.")

    # ── 2. DNS Security Records ──────────────────────────────────────────────
    import dns.resolver

    txt_records = dns_records.get("TXT", [])
    has_spf = any("v=spf1" in r for r in txt_records)

    has_dmarc = False
    try:
        answers  = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=DMARC1" in rdata.to_text() for rdata in answers)
    except Exception:
        pass

    if not has_spf:
        deductions += WEIGHTS["no_spf"]
        warnings.append(
            "No SPF record found. SPF prevents email spoofing from this domain."
        )
    else:
        positives.append("✓ SPF record present.")

    if not has_dmarc:
        deductions += WEIGHTS["no_dmarc"]
        warnings.append(
            "No DMARC record found. DMARC provides policy-based protection against email abuse."
        )
    else:
        positives.append("✓ DMARC record present.")

    # ── 3. TLS / HTTPS ───────────────────────────────────────────────────────
    if not tls_info.get("valid"):
        deductions += WEIGHTS["no_https"]
        err = tls_info.get("error", "")
        if "timed out" in err.lower() or "connection" in err.lower():
            warnings.append(
                "Could not connect on port 443 — site may not support HTTPS, "
                "or the server timed out."
            )
        else:
            warnings.append(
                f"Invalid or untrusted TLS certificate: {err or 'Unknown error'}. "
                "HTTPS is essential for secure communication."
            )
    else:
        positives.append(
            f"✓ Valid TLS certificate issued by {tls_info.get('issuer', 'Unknown CA')}."
        )

    # ── 4. HTTP Security Headers ─────────────────────────────────────────────
    headers = headers_info.get("headers", {})

    if not headers.get("Strict-Transport-Security"):
        deductions += WEIGHTS["no_hsts"]
        warnings.append(
            "Missing Strict-Transport-Security (HSTS) header. "
            "Without HSTS, users can be silently downgraded to HTTP."
        )
    else:
        positives.append("✓ HSTS header present.")

    # CSP is a 'nice-to-have' — many major sites omit it, so smaller penalty
    if not headers.get("Content-Security-Policy"):
        deductions += WEIGHTS["no_csp"]
        warnings.append(
            "Missing Content-Security-Policy (CSP) header. "
            "CSP helps mitigate XSS attacks (note: many large sites do not set this header)."
        )
    else:
        positives.append("✓ Content-Security-Policy header present.")

    # ── Final Score ──────────────────────────────────────────────────────────
    trust_score = max(0, min(100, 100 - deductions))

    # Determine verdict
    if trust_score >= 85:
        verdict = "Trusted"
    elif trust_score >= 60:
        verdict = "Low Risk"
    elif trust_score >= 40:
        verdict = "Moderate Risk"
    else:
        verdict = "High Risk"

    return {
        "domain":    domain,
        "score":     trust_score,
        "verdict":   verdict,
        "deductions": deductions,
        "warnings":  warnings,
        "positives": positives,
        "data": {
            "whois":   whois_data,
            "dns":     dns_records,
            "tls":     tls_info,
            "headers": headers_info,
        }
    }
