import os
import time
import math
import re
from urllib.parse import urlparse
from collections import Counter
import joblib
import pandas as pd
import numpy as np

class ThreatIntelPredictor:
    """
    ThreatIntelPredictor manages inference for:
    1. Fast Lexical Random Forest (URL string analysis)
    2. Network Infrastructure Random Forest (Scraped features)
    3. Isolation Forest Anomaly Detector (Zero-day & outlier detection)
    """

    LEXICAL_COLS = [
        'url_len', 'domain_len', 'path_len', 'dot_count', 'hyphen_count',
        'underline_count', 'slash_count', 'question_count', 'equal_count', 'at_count',
        'digit_count', 'digit_ratio', 'domain_entropy', 'is_ip', 'subdomain_count',
        'has_bracket_dot', 'has_paren_dot', 'has_hxxp'
    ]

    NETWORK_COLS = [
        'age_days', 'whois_has_error', 'has_spf', 'has_dmarc', 'has_mx',
        'dns_has_error', 'tls_valid', 'tls_has_error', 'has_hsts', 'has_csp',
        'has_x_frame_options', 'has_x_content_type_options'
    ]

    ANOMALY_COLS = [
        'age_days', 'has_spf', 'has_dmarc', 'has_mx',
        'dns_has_error', 'tls_valid', 'tls_has_error',
        'has_hsts', 'has_csp', 'has_x_frame_options'
    ]

    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        self.lexical_model = None
        self.network_model = None
        self.iso_forest = None
        self.scaler = None
        self.load_models()

    def load_models(self):
        """Loads all serialized models with graceful fallback."""
        lex_path = os.path.join(self.models_dir, "lexical_rf_model.joblib")
        net_path = os.path.join(self.models_dir, "network_rf_model.joblib")
        iso_path = os.path.join(self.models_dir, "isolation_forest.joblib")
        scaler_path = os.path.join(self.models_dir, "scaler.joblib")

        try:
            if os.path.exists(lex_path):
                self.lexical_model = joblib.load(lex_path)
        except Exception as e:
            print(f"[WARN] Failed to load lexical model: {e}")

        try:
            if os.path.exists(net_path):
                self.network_model = joblib.load(net_path)
        except Exception as e:
            print(f"[WARN] Failed to load network model: {e}")

        try:
            if os.path.exists(iso_path) and os.path.exists(scaler_path):
                self.iso_forest = joblib.load(iso_path)
                self.scaler = joblib.load(scaler_path)
        except Exception as e:
            print(f"[WARN] Failed to load anomaly model/scaler: {e}")

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def extract_lexical_features(self, url: str) -> dict:
        """Extracts 18 lexical features from raw URL string."""
        url_clean = (url or "").strip()
        has_bracket_dot = int('[.]' in url_clean)
        has_paren_dot = int('(dot)' in url_clean.lower())
        has_hxxp = int(url_clean.lower().startswith('hxxp'))

        norm_url = url_clean.replace('[.]', '.').replace('(dot)', '.')
        if norm_url.lower().startswith('hxxp'):
            norm_url = 'http' + norm_url[4:]
        if not norm_url.startswith(('http://', 'https://', 'ftp://')):
            # If user provided a bare domain like "google.com", normalize with www. to match dataset distribution
            if '.' in norm_url and not norm_url.startswith('www.') and norm_url.count('.') == 1:
                norm_url = 'https://www.' + norm_url
            else:
                norm_url = 'https://' + norm_url

        try:
            parsed = urlparse(norm_url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
        except Exception:
            hostname = ""
            path = ""

        # Measure on normalized URL to match training distribution of urldata.csv
        eval_url = norm_url
        url_len = len(eval_url)
        domain_len = len(hostname)
        path_len = len(path)

        dot_count = eval_url.count('.')
        hyphen_count = eval_url.count('-')
        underline_count = eval_url.count('_')
        slash_count = eval_url.count('/')
        question_count = eval_url.count('?')
        equal_count = eval_url.count('=')
        at_count = eval_url.count('@')

        digit_count = sum(c.isdigit() for c in eval_url)
        digit_ratio = (digit_count / url_len) if url_len > 0 else 0.0
        domain_entropy = self.shannon_entropy(hostname)
        is_ip = int(bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname)))
        subdomain_count = max(0, hostname.count('.') - 1) if hostname else 0

        return {
            'url_len': url_len,
            'domain_len': domain_len,
            'path_len': path_len,
            'dot_count': dot_count,
            'hyphen_count': hyphen_count,
            'underline_count': underline_count,
            'slash_count': slash_count,
            'question_count': question_count,
            'equal_count': equal_count,
            'at_count': at_count,
            'digit_count': digit_count,
            'digit_ratio': round(digit_ratio, 4),
            'domain_entropy': round(domain_entropy, 4),
            'is_ip': is_ip,
            'subdomain_count': subdomain_count,
            'has_bracket_dot': has_bracket_dot,
            'has_paren_dot': has_paren_dot,
            'has_hxxp': has_hxxp,
        }

    def predict_lexical(self, url: str) -> dict:
        """Runs fast in-memory lexical URL prediction."""
        t0 = time.perf_counter()
        feats = self.extract_lexical_features(url)
        df_feat = pd.DataFrame([feats])[self.LEXICAL_COLS]

        if self.lexical_model is not None:
            prob_malicious = float(self.lexical_model.predict_proba(df_feat)[0][1])
            is_malicious = bool(prob_malicious >= 0.5)
        else:
            prob_malicious = 0.5
            is_malicious = False

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "risk_score": round(prob_malicious * 100, 1),
            "malicious_probability": round(prob_malicious, 4),
            "verdict": "Malicious" if is_malicious else "Benign",
            "confidence": round(abs(prob_malicious - 0.5) * 2, 2),
            "entropy": feats['domain_entropy'],
            "is_ip_address": bool(feats['is_ip']),
            "obfuscation_detected": bool(feats['has_bracket_dot'] or feats['has_paren_dot'] or feats['has_hxxp']),
            "latency_ms": latency_ms
        }

    def parse_scraper_features(self, scraper_data: dict) -> dict:
        """Parses scraper raw dict output into model feature representations."""
        whois_data = scraper_data.get("whois", {}) or {}
        dns_data = scraper_data.get("dns", {}) or {}
        tls_data = scraper_data.get("tls", {}) or {}
        headers_data = (scraper_data.get("headers", {}) or {}).get("headers", {}) or {}

        age_days = whois_data.get("age_days")
        if age_days is None:
            age_days = -1.0
        else:
            age_days = float(age_days)

        whois_has_error = 1 if whois_data.get("error") else 0

        txt_recs = dns_data.get("TXT", []) or []
        has_spf = 1 if any("v=spf1" in str(r) for r in txt_recs) else 0
        has_dmarc = 1 if any("v=DMARC1" in str(r) for r in txt_recs) else 0
        has_mx = 1 if len(dns_data.get("MX", []) or []) > 0 else 0
        dns_has_error = 1 if dns_data.get("error") else 0

        tls_valid = 1 if bool(tls_data.get("valid")) else 0
        tls_has_error = 1 if tls_data.get("error") else 0

        has_hsts = 1 if bool(headers_data.get("Strict-Transport-Security")) else 0
        has_csp = 1 if bool(headers_data.get("Content-Security-Policy")) else 0
        has_x_frame = 1 if bool(headers_data.get("X-Frame-Options")) else 0
        has_x_content = 1 if bool(headers_data.get("X-Content-Type-Options")) else 0

        return {
            'age_days': age_days,
            'whois_has_error': whois_has_error,
            'has_spf': has_spf,
            'has_dmarc': has_dmarc,
            'has_mx': has_mx,
            'dns_has_error': dns_has_error,
            'tls_valid': tls_valid,
            'tls_has_error': tls_has_error,
            'has_hsts': has_hsts,
            'has_csp': has_csp,
            'has_x_frame_options': has_x_frame,
            'has_x_content_type_options': has_x_content
        }

    def predict_network(self, scraper_data: dict) -> dict:
        """Predicts risk based on scraped network infrastructure features."""
        parsed = self.parse_scraper_features(scraper_data)
        df_net = pd.DataFrame([parsed])[self.NETWORK_COLS]

        if self.network_model is not None:
            prob_malicious = float(self.network_model.predict_proba(df_net)[0][1])
            verdict = "Malicious" if prob_malicious >= 0.5 else "Benign"
        else:
            prob_malicious = 0.5
            verdict = "Unknown"

        return {
            "risk_score": round(prob_malicious * 100, 1),
            "malicious_probability": round(prob_malicious, 4),
            "verdict": verdict
        }

    def predict_anomaly(self, scraper_data: dict) -> dict:
        """Computes unsupervised anomaly score using Isolation Forest."""
        parsed = self.parse_scraper_features(scraper_data)
        df_anom = pd.DataFrame([parsed])[self.ANOMALY_COLS]

        if self.iso_forest is not None and self.scaler is not None:
            scaled = self.scaler.transform(df_anom)
            raw_score = float(self.iso_forest.decision_function(scaled)[0])
            is_anomaly = bool(self.iso_forest.predict(scaled)[0] == -1)
            # Normalize decision score to roughly [0, 1] range
            # Decision scores typically range from -0.3 (extreme anomaly) to +0.3 (normal)
            normalized_score = max(0.0, min(1.0, (0.25 - raw_score) / 0.5))
        else:
            normalized_score = 0.0
            is_anomaly = False

        if normalized_score > 0.65:
            anomaly_level = "High"
        elif normalized_score > 0.45:
            anomaly_level = "Moderate"
        else:
            anomaly_level = "Normal"

        return {
            "anomaly_score": round(normalized_score, 4),
            "is_anomaly": is_anomaly,
            "anomaly_level": anomaly_level,
            "zero_day_suspect": bool(is_anomaly and normalized_score > 0.60)
        }

    def predict_all(self, url: str, domain: str, scraper_data: dict, smuggling: dict = None) -> dict:
        """
        Combines Lexical, Network ML, and Anomaly Detection into a unified AI assessment.
        Includes adversarial URL smuggling signals if multiple protocol schemes or lures were detected.
        """
        lexical_res = self.predict_lexical(url or domain)
        network_res = self.predict_network(scraper_data)
        anomaly_res = self.predict_anomaly(scraper_data)

        # Unified Composite Risk Score
        # 40% lexical + 45% network ML + 15% anomaly bonus
        lex_risk = lexical_res["risk_score"]
        net_risk = network_res["risk_score"]
        anom_penalty = 15.0 if anomaly_res["zero_day_suspect"] else (anomaly_res["anomaly_score"] * 10.0)

        composite_risk = (0.40 * lex_risk) + (0.45 * net_risk) + anom_penalty
        
        # If adversarial smuggling is detected, ensure the active payload threat is highlighted
        if smuggling and smuggling.get("is_concatenated"):
            composite_risk = max(composite_risk, 80.0)

        composite_risk = round(max(0.0, min(100.0, composite_risk)), 1)

        # Determine composite verdict
        if composite_risk >= 70:
            composite_verdict = "High Risk"
        elif composite_risk >= 45:
            composite_verdict = "Moderate Risk"
        elif composite_risk >= 25:
            composite_verdict = "Low Risk"
        else:
            composite_verdict = "Trusted"

        result = {
            "composite_ai_risk_score": composite_risk,
            "composite_verdict": composite_verdict,
            "lexical": lexical_res,
            "network_ml": network_res,
            "anomaly": anomaly_res
        }
        if smuggling:
            result["smuggling"] = smuggling
        return result
