from flask import Flask, request, jsonify
from flask_cors import CORS
from scraper.scoring import calculate_risk
import os

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "*")}})

@app.route("/", methods=["GET", "HEAD"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or not data.get("domain"):
        return jsonify({"error": "No domain provided"}), 400
        
    domain = data["domain"].strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]
        
    try:
        result = calculate_risk(domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1").lower() in {"1", "true", "yes", "on"}
    app.run(host=host, port=port, debug=debug)
