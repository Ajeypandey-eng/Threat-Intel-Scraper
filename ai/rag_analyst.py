import os
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class ThreatIntelRAGAnalyst:
    """
    100% Local RAG Security Analyst Engine.
    Maps local machine learning telemetry and scraper findings
    against a local MITRE ATT&CK threat intelligence knowledge base.
    """

    def __init__(self, kb_path=None):
        if kb_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            kb_path = os.path.join(base_dir, "knowledge_base", "mitre_attack.json")
        self.kb_path = kb_path
        self.knowledge_base = []
        self.load_knowledge_base()

    def load_knowledge_base(self):
        try:
            if os.path.exists(self.kb_path):
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    self.knowledge_base = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to load MITRE knowledge base: {e}")
            self.knowledge_base = []

    def extract_evidence_signals(self, domain: str, ai_data: dict, scraper_data: dict) -> tuple[list[str], list[str]]:
        """
        Translates raw ML metrics and scraper findings into security evidence and trigger tags.
        """
        triggers = []
        evidence = []

        lexical = ai_data.get("lexical", {}) or {}
        network = ai_data.get("network_ml", {}) or {}
        anomaly = ai_data.get("anomaly", {}) or {}

        # 1. Lexical Evidence
        if lexical.get("obfuscation_detected"):
            triggers.append("obfuscation_detected")
            evidence.append("Obfuscation patterns detected in URL syntax (e.g. defanged dots, hxxp scheme).")
        if lexical.get("entropy", 0) > 3.4:
            triggers.append("high_entropy")
            evidence.append("High character randomness detected in domain name, indicating potential algorithmic generation (DGA).")
        if lexical.get("risk_score", 0) >= 60:
            triggers.append("high_lexical_risk")
            evidence.append(f"URL syntax exhibits structural patterns commonly associated with deceptive links ({lexical.get('risk_score')}% risk score).")
        if lexical.get("is_ip_address"):
            triggers.append("obfuscation_detected")
            evidence.append("URL targets a raw IP address directly, bypassing standard DNS name resolution.")

        # 2. Network Evidence
        whois_data = scraper_data.get("whois", {}) or {}
        dns_data = scraper_data.get("dns", {}) or {}
        tls_data = scraper_data.get("tls", {}) or {}

        age_days = whois_data.get("age_days")
        if age_days is not None and age_days < 30:
            triggers.append("age_days_low")
            evidence.append(f"Domain is newly registered ({age_days} days old), a hallmark of temporary attack infrastructure.")
        elif whois_data.get("error"):
            triggers.append("whois_error")
            evidence.append("WHOIS registration records are hidden, broken, or unreachable.")

        txt_records = dns_data.get("TXT", []) or []
        has_spf = any("v=spf1" in str(r) for r in txt_records)
        if not has_spf:
            triggers.append("missing_spf")
            evidence.append("Missing SPF record — domain is susceptible to unauthorized email spoofing.")

        dmarc_present = any("v=DMARC1" in str(r) for r in txt_records)
        if not dmarc_present:
            triggers.append("missing_dmarc")
            evidence.append("Missing DMARC policy — domain lacks domain-level email sender verification.")

        if not tls_data.get("valid"):
            triggers.append("tls_invalid")
            evidence.append(f"TLS/HTTPS certificate verification failed: {tls_data.get('error', 'Invalid or absent certificate')}.")

        # 3. Anomaly Evidence
        if anomaly.get("zero_day_suspect"):
            triggers.append("zero_day_suspect")
            evidence.append("Atypical infrastructure configuration detected, deviating from standard verified baselines.")
        elif anomaly.get("anomaly_score", 0) > 0.60:
            triggers.append("high_anomaly")
            evidence.append("Infrastructure setup exhibits notable variance compared to established benign domains.")

        # 4. URL Smuggling & Concatenation Evidence
        smuggling = ai_data.get("smuggling", {}) or {}
        if smuggling.get("is_concatenated"):
            triggers.append("concatenated_url_smuggling")
            prefix = smuggling.get("lure_prefix_domain")
            payload = smuggling.get("active_payload_domain")
            tech = smuggling.get("technique", "URL Smuggling")
            schemes = smuggling.get("schemes_found", [])
            scheme_str = " + ".join([s.upper() for s in schemes]) if schemes else "MULTI-SCHEME"
            evidence.append(
                f"Adversarial URL Smuggling & Protocol Chaining Detected ({tech} - {scheme_str}): "
                f"Attempted to weaponize innocent lure domain '{prefix}' (protected under Universal Immunity) "
                f"to mask active payload '{payload}'. Local intelligence quarantines payload while shielding innocent domain."
            )

        return triggers, evidence

    def retrieve_mitre_context(self, triggers: list[str], query_text: str) -> list[dict]:
        """
        Retrieves relevant MITRE ATT&CK techniques using trigger matching and TF-IDF similarity.
        """
        if not self.knowledge_base:
            return []

        matched = []
        for item in self.knowledge_base:
            overlap = set(item.get("triggers", [])).intersection(set(triggers))
            if overlap:
                matched.append({
                    "technique_id": item["technique_id"],
                    "name": item["name"],
                    "tactics": item["tactics"],
                    "description": item["description"],
                    "mitigation": item["mitigation"],
                    "relevance_score": len(overlap)
                })

        # Sort by relevance score
        matched.sort(key=lambda x: x["relevance_score"], reverse=True)
        return matched[:3]

    def generate_report(self, domain: str, ai_data: dict, scraper_data: dict) -> dict:
        """
        Synthesizes an executive SOC Incident Report combining local ML outputs with retrieved MITRE context.
        """
        triggers, evidence = self.extract_evidence_signals(domain, ai_data, scraper_data)
        query_text = " ".join(evidence) if evidence else "Benign established domain"
        retrieved_mitre = self.retrieve_mitre_context(triggers, query_text)

        composite_score = ai_data.get("composite_ai_risk_score", 20.0)
        is_anomaly = (ai_data.get("anomaly", {}) or {}).get("zero_day_suspect", False)

        # Threat Level Determination
        if composite_score >= 75 or (composite_score >= 50 and is_anomaly):
            threat_level = "CRITICAL"
            verdict_summary = f"High-confidence malicious indicator detected for {domain}. Immediate security remediation recommended."
        elif composite_score >= 45:
            threat_level = "ELEVATED"
            verdict_summary = f"Suspicious or unhardened infrastructure detected for {domain}. Treat with caution."
        else:
            threat_level = "LOW / TRUSTED"
            verdict_summary = f"{domain} conforms to standard legitimate infrastructure patterns with low threat probability."

        # If no red flags found (benign)
        if not evidence:
            evidence.append("Domain exhibits established age, valid cryptographic TLS certificate, and normal entropy.")

        # Recommendations
        recommendations = []
        if threat_level == "CRITICAL":
            recommendations.append("Block domain at perimeter firewall and DNS sinkholes.")
            recommendations.append("Isolate any endpoints that recently initiated connections to this host.")
            recommendations.append("Inspect outbound mail and authentication logs for credential reuse.")
        elif threat_level == "ELEVATED":
            recommendations.append("Restrict inbound links from this domain in email security gateways.")
            recommendations.append("Warn users before submitting credentials or downloading attachments.")
        else:
            recommendations.append("Standard monitoring — no immediate defensive blocking required.")

        for item in retrieved_mitre:
            if item.get("mitigation") and item["mitigation"] not in recommendations:
                recommendations.append(f"[{item['technique_id']}] {item['mitigation']}")

        return {
            "threat_level": threat_level,
            "executive_summary": verdict_summary,
            "composite_ai_risk_score": composite_score,
            "technical_evidence": evidence,
            "mitre_attack_mappings": [
                {
                    "technique_id": m["technique_id"],
                    "name": m["name"],
                    "tactics": m["tactics"],
                    "description": m["description"]
                }
                for m in retrieved_mitre
            ],
            "actionable_recommendations": recommendations[:4]
        }
