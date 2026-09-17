from flask import Flask, request, jsonify
from flask_cors import CORS
from scraper.scoring import calculate_risk
from ai.predictor import ThreatIntelPredictor
from ai.rag_analyst import ThreatIntelRAGAnalyst
from ai.smuggling_detector import detect_url_smuggling, extract_clean_domain_str
import os
import json

import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

def extract_clean_domain(raw_input: str) -> str:
    return extract_clean_domain_str(raw_input)

# Initialize AI Inference Engine & Local RAG Analyst
predictor = ThreatIntelPredictor()
analyst = ThreatIntelRAGAnalyst()

@app.route("/", methods=["GET", "HEAD"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Threat Intelligence Scraper AI API",
        "models_loaded": {
            "lexical": predictor.lexical_model is not None,
            "network_ml": predictor.network_model is not None,
            "isolation_forest": predictor.iso_forest is not None,
            "rag_knowledge_base": len(analyst.knowledge_base) > 0
        }
    })

@app.route("/api/scan-url", methods=["POST"])
def scan_url_fast():
    """
    Tier-1 Fast-Path Endpoint:
    Sub-millisecond Lexical ML URL scanner without network scraping latency.
    """
    data = request.json or {}
    url = data.get("url") or data.get("domain")
    if not url:
        return jsonify({"error": "No URL or domain provided"}), 400

    try:
        prediction = predictor.predict_lexical(url)
        return jsonify({
            "target": url,
            "analysis_type": "lexical_fast_path",
            "lexical": prediction
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze_domain():
    """
    On-demand SOC Analyst Report generation.
    """
    data = request.json or {}
    domain = (data.get("domain") or data.get("url") or "").strip().lower()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
        
    try:
        result = calculate_risk(domain)
        ai_assessment = predictor.predict_all(
            url=domain,
            domain=domain,
            scraper_data=result.get("data", {})
        )
        report = analyst.generate_report(domain, ai_assessment, result.get("data", {}))
        return jsonify({
            "domain": domain,
            "analyst_report": report
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

PROTECTED_DOMAINS = {
    "onrender.com", "github.com", "google.com", "microsoft.com", 
    "cloudflare.com", "localhost", "127.0.0.1", "apple.com", "amazon.com"
}

@app.route("/api/report-threat", methods=["POST", "OPTIONS"])
def report_threat():
    """
    Crowdsourced Threat IoC Reporting Endpoint.
    Guarded by:
    1. Infrastructure Immunity Whitelist (cannot report own app or major backbones)
    2. Framing & URL Smuggling Protection (protects both MINOR & major domains from malicious blacklisting)
    3. Intelligence Gating (only domains verified as risky by models can be submitted)
    4. Human Verification challenge
    """
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    raw_domain = (data.get("domain") or "").strip()
    domain = extract_clean_domain(raw_domain).lower()
    lure_prefix = (data.get("lure_prefix") or "").strip().lower()
    risk_score = float(data.get("risk_score", 0))
    threat_level = str(data.get("threat_level", "ELEVATED")).upper()
    human_verified = bool(data.get("human_verified", False))

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # 1. Protection against Griefing / Self-reporting for major infrastructure
    for protected in PROTECTED_DOMAINS:
        if domain == protected or domain.endswith("." + protected):
            return jsonify({
                "error": f"Domain '{domain}' is protected infrastructure and cannot be reported."
            }), 403

    # 2. Universal Framing & Smuggling Protection (Protects ALL minor and major domains!)
    smuggling = detect_url_smuggling(raw_domain)
    if smuggling["is_concatenated"]:
        # If user tried to report the lure prefix domain (e.g. smallbakery.com), BLOCK IT
        if domain == smuggling["lure_prefix_domain"]:
            return jsonify({
                "error": f"Submission blocked: '{domain}' is an innocent domain framed in a concatenated URL attack. Public reporting is blocked to protect innocent domain owners from false-positive blocklisting."
            }), 403
        # Auto-route report to the actual payload
        domain = smuggling["active_payload_domain"]

    if lure_prefix and domain == lure_prefix:
        return jsonify({
            "error": f"Submission blocked: '{domain}' is protected as an innocent framed domain. Only the verified payload can be reported."
        }), 403

    # 3. Intelligence Gating: Only suspicious or malicious domains can be reported
    if risk_score < 45 and threat_level not in {"CRITICAL", "HIGH", "ELEVATED"}:
        return jsonify({
            "error": "Submission rejected: Automated intelligence evaluated this domain as low risk. Only suspicious or malicious domains can be reported."
        }), 400

    # 4. Human Verification Check
    if not human_verified:
        return jsonify({"error": "Human verification challenge failed or missing."}), 400

    # 5. Save to local Community Feed
    os.makedirs("data", exist_ok=True)
    reports_file = os.path.join("data", "community_reports.json")
    reports = []
    if os.path.exists(reports_file):
        try:
            with open(reports_file, "r", encoding="utf-8") as f:
                reports = json.load(f)
        except Exception:
            reports = []

    import time
    import uuid

    report_entry = {
        "report_id": f"ioc-{uuid.uuid4().hex[:8]}",
        "domain": domain,
        "risk_score": risk_score,
        "threat_level": data.get("threat_level", "ELEVATED"),
        "submitted_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "status": "PENDING_TRIAGE",
        "feeds": ["URLhaus Community", "PhishTank", "Local Threat Feed"]
    }
    reports.insert(0, report_entry)

    with open(reports_file, "w", encoding="utf-8") as f:
        json.dump(reports[:100], f, indent=2)

    return jsonify({
        "status": "success",
        "message": f"Domain {domain} submitted to community threat triage successfully.",
        "report": report_entry,
        "external_submission_urls": {
            "urlhaus": "https://urlhaus.abuse.ch/browse/",
            "phishtank": "https://phishtank.org/"
        }
    })

@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Full Threat Intelligence Scan:
    Returns original heuristic baseline, raw infrastructure data,
    the AI assessment (Lexical, Network ML, Isolation Forest Anomaly),
    AND the Local RAG MITRE ATT&CK Security Analyst Report.
    Includes Adversarial Concatenated URL Smuggling defense to protect innocent minor/major domains.
    """
    data = request.json or {}
    raw_input = (data.get("domain") or data.get("url") or "").strip()
    if not raw_input:
        return jsonify({"error": "No domain provided"}), 400
        
    # Detect if multiple URLs/protocols (e.g. http, https, ftp, ftps) were concatenated
    smuggling = detect_url_smuggling(raw_input)
    
    if smuggling["is_concatenated"]:
        scan_target_domain = smuggling["active_payload_domain"]
        scan_target_url = smuggling["active_payload_raw"]
    else:
        scan_target_domain = extract_clean_domain(raw_input)
        scan_target_url = raw_input
        
    try:
        # 1. Run network scraper and heuristic scoring on the active payload target
        result = calculate_risk(scan_target_domain)
        
        # 2. Run AI Inference Pipeline
        ai_assessment = predictor.predict_all(
            url=scan_target_url,
            domain=scan_target_domain,
            scraper_data=result.get("data", {}),
            smuggling=smuggling
        )
        
        # 3. Generate Local RAG MITRE ATT&CK Analyst Report
        analyst_report = analyst.generate_report(
            domain=scan_target_domain,
            ai_data=ai_assessment,
            scraper_data=result.get("data", {})
        )
        ai_assessment["analyst_report"] = analyst_report
        
        # 4. Attach to response (100% backward compatible)
        result["ai"] = ai_assessment
        result["analyst_report"] = analyst_report
        result["smuggling"] = smuggling
        if smuggling["is_concatenated"]:
            result["lure_prefix_domain"] = smuggling["lure_prefix_domain"]
            result["active_payload_domain"] = scan_target_domain
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5001"))
    debug = os.getenv("FLASK_DEBUG", "1").lower() in {"1", "true", "yes", "on"}
    app.run(host=host, port=port, debug=debug)
