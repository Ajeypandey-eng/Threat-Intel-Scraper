# Threat Intelligence Scraper

> **Automated Domain & Infrastructure Risk Scanner with AI Threat Engine & Anti-Smuggling Defense**  
> by [Ajey Pandey](https://github.com/Ajeypandey-eng)

A modern, high-performance OSINT and Threat Intelligence platform that takes any URL or domain name, queries public data sources — WHOIS, DNS, TLS certificates, and HTTP security headers — and pairs rule-based heuristic scoring with an advanced **Dual-Engine AI Threat Assessment** and **Universal Smuggling Detector**.

Built with a **Python Flask & Scikit-Learn** backend and a **React + Vite** frontend featuring animated Skiper UI components, a minimalist monochrome aesthetic, and full mobile responsiveness.

---

## Key Features

### 1. Dual-Engine Intelligence & Scoring
- **Rule-Based Trust Score (0–100)**: Evaluates infrastructure basics including domain age, email authentication (SPF, DMARC), TLS validity, and HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`).
- **AI Threat Engine (0–100% Risk)**:
  - **Lexical Random Forest**: Analyzes 18 structural URL attributes (entropy, length ratios, IP presence, bracket/hxxp defanging).
  - **Network Infrastructure Classifier**: Machine learning evaluation of DNS, TLS, and registrar patterns.
  - **Isolation Forest Anomaly Detector**: Unsupervised outlier analysis designed to flag novel zero-day attack vectors.
  - **Composite AI Verdict**: Instant synthesis across models categorizing threats as Clean, Low Risk, Suspicious, or Malicious.

### 2. Universal Smuggling & Protocol Chaining Defense
- **Concatenated URL Detection**: Detects evasive attacks where an attacker concatenates a benign URL with a malicious payload (e.g., `google.comhttps://114.239.63.214/...`) to bypass scanners.
- **Multi-Protocol Inspection**: Identifies chaining across `http`, `https`, `ftp`, `ftps`, and defanged `hxxp` schemes.
- **Universal Domain Immunity**: Automatically grants immunity to framed benign lure domains (both major brands and minor websites), isolating and quarantining only the active malicious payload.

### 3. Community Threat IoC Reporting & Interactive CAPTCHA
- **Interactive 3x3 Visual CAPTCHA**: Enforces human verification via randomized target object puzzles before submitting reports.
- **Community IoC Syndication**: Publishes validated threat indicators with syndication across simulated feeds (URLhaus Community, PhishTank, Local Threat Feed).
- **Responsive & Scrollable Modal**: Seamlessly adapts to all screen sizes from desktop monitors down to mobile viewports (e.g. 360px width) with sticky headers and action bars.

### 4. Modern UI & Aesthetics
- **Monochrome Minimalist Palette**: Clean dark/light theme parity with subtle emerald and ruby status accents.
- **Theme-Adaptive Inputs**: High-contrast, dynamic input coloring and caret animations powered by Skiper UI and Framer Motion.
- **Comprehensive Legal & Ethics Center**: Terms of Service, Ethical Use Policy, Disclaimer, and Responsible Disclosure built directly into the UI.

---

## Architecture

```
threat-intel-scraper/
│
├── server.py              # Flask API backend (Dual engine, smuggling detection, IoC triage)
├── requirements.txt       # Python backend dependencies
├── Procfile               # Gunicorn deployment config
├── render.yaml            # Render blueprint (API + Frontend)
├── package.json           # Root convenience scripts (npm run dev/build)
│
├── ai/                    # Machine learning & AI modules
│   ├── predictor.py       # Multi-model inference engine (Lexical RF, Network RF, Isolation Forest)
│   ├── smuggling_detector.py # Universal smuggling & protocol chaining detector
│   ├── rag_analyst.py     # RAG threat analysis agent
│   └── knowledge_base/    # MITRE ATT&CK mappings & threat taxonomies
│
├── models/                # Serialized trained scikit-learn models (.joblib)
│   ├── lexical_rf_model.joblib
│   ├── network_rf_model.joblib
│   ├── isolation_forest.joblib
│   └── scaler.joblib
│
├── scraper/               # Python intelligence collection modules
│   ├── whois_lookup.py    # WHOIS domain registration data
│   ├── dns_lookup.py      # DNS record resolution (A, MX, TXT, NS, AAAA)
│   ├── tls_lookup.py      # TLS certificate inspection
│   ├── http_headers.py    # HTTP security header retrieval
│   └── scoring.py         # Heuristic scoring engine
│
├── data/                  # Persistent runtime data
│   └── community_reports.json # Community IoC threat reports
│
├── notebooks/             # Research & model training notebooks
│   ├── baseline_model.ipynb
│   ├── lexical_model.ipynb
│   ├── anomaly_detection_model.ipynb
│   └── nlp_content_model.ipynb
│
├── scripts/               # Training & export utilities
│   └── export_models.py
│
└── frontend/              # React 18 + Vite web application
    ├── src/
    │   ├── App.tsx                    # Main dashboard layout & dual-engine result views
    │   ├── index.css                  # Theme variables & design system
    │   ├── main.tsx                   # React root + theme provider
    │   └── components/
    │       ├── CaptchaPuzzle.tsx      # Interactive 3x3 visual CAPTCHA
    │       ├── Skiper26.tsx           # Theme toggle (animated transition)
    │       ├── Skiper31.tsx           # Scroll-reveal text (Lenis + Framer Motion)
    │       ├── Skiper58.tsx           # Text roll navigation
    │       ├── Skiper106.tsx          # Smooth spring caret input
    │       └── Footer.tsx             # Legal, ethics & compliance accordion
    ├── tailwind.config.js
    └── postcss.config.js
```

---

## Getting Started

### Prerequisites
- **Python 3.9+**
- **Node.js 18+**

### 1. Clone the repository
```bash
git clone https://github.com/Ajeypandey-eng/Threat-Intel-Scraper.git
cd Threat-Intel-Scraper
```

### 2. Set up the Python backend
```bash
# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the application

You can start both services from root or individually:

#### Option A: Root script
```bash
# Run backend in terminal 1
python server.py

# Run frontend in terminal 2
npm run dev
```

#### Option B: Frontend directly
```bash
cd frontend
npm install
npm run dev
```

- **Backend API**: `http://localhost:5001`
- **Frontend Dashboard**: `http://localhost:5173`

---

## How Scoring Works

### Heuristic Rule-Based Deductions
The rule-based baseline starts at 100 and applies risk deductions:

| Signal | Deduction | Reason |
|---|---|---|
| Domain < 30 days old | −40 | Newly registered domains frequently indicate disposable phishing campaigns |
| Domain 30–180 days old | −20 | Relatively young domain, elevated risk profile |
| WHOIS unavailable | −10 | Inability to verify ownership or registration dates |
| No SPF record | −10 | High email spoofing exposure |
| No DMARC record | −10 | Lack of domain-level email authentication enforcement |
| Invalid / Missing TLS | −25 | Plaintext HTTP transmission — critical security flaw |
| No HSTS header | −10 | Susceptible to SSL-stripping and downgrade attacks |
| No CSP header | −5 | Increased Cross-Site Scripting (XSS) exposure |

### Dual Engine Verdict Scale

| Rule-Based Trust Score | Heuristic Verdict | AI Composite Risk Score | AI Assessment |
|---|---|---|---|
| 85–100 | **Trusted** | 0% – 25% | **Clean** |
| 60–84 | **Low Risk** | 26% – 50% | **Low Risk** |
| 40–59 | **Moderate Risk** | 51% – 75% | **Suspicious** |
| 0–39 | **High Risk** | 76% – 100% | **Malicious** |

---

## Anti-Smuggling Protection in Action

When an input contains chained schemes or concatenated URLs such as:
```text
https://trusted-site.orghttp://114.239.63.214:39292/payload
```
The scanner automatically activates the **Universal Smuggling Detector**:
1. **Separates Chained Protocols**: Flags the anomaly (`http` following `.org`).
2. **Shields the Lure**: Assigns `Immunity Active` to `trusted-site.org`, preventing false-positive flagging.
3. **Quarantines the Payload**: Evaluates and isolates `114.239.63.214` as the active target for threat triage and IoC logging.

---

## Deployment

The application is structured for instant deployment on [Render](https://render.com) using the included `render.yaml`:

- **API Service**: Python web service running `gunicorn server:app --bind 0.0.0.0:$PORT`
- **Frontend Service**: Node web service building static assets and serving them via `npx serve`
- **Config & Environment**: Sample templates provided in `.env.example` and `frontend/.env.example`.

---

## Ethical Use & Compliance

This software is designed exclusively for **authorized security audits, threat research, and educational analysis**. Users must only scan assets they own or have obtained explicit authorization to test. 

Consult the in-app footer for the complete **Terms of Service**, **Ethical Use Policy**, and **Responsible Disclosure Guidelines**.

---

## License

Distributed under the **MIT License**. Free for personal, academic, and commercial security research with attribution.

*Maintained with care by [Ajey Pandey](https://github.com/Ajeypandey-eng)*
