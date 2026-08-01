# 🔍 Threat Intelligence Scraper

> **Automated Domain & Infrastructure Risk Scanner**  
> by [Ajey Pandey](https://github.com/ajeypandey)

A lightweight, open-source OSINT tool that takes a domain name, queries multiple public data sources — WHOIS, DNS, TLS certificates, and HTTP security headers — and computes an instant **Trust Score (0–100)** with a detailed breakdown of risk factors.

Built with a **Python Flask** backend and a **React + Vite** frontend featuring animated Skiper UI components, a minimalist black-and-white aesthetic, and a smooth dark mode toggle.

---

## ✨ Features

- **Trust Scoring (0–100)** — Higher is safer. Scores are broken into: Trusted / Low Risk / Moderate Risk / High Risk
- **WHOIS Analysis** — Domain age, registrar, creation & expiration dates
- **DNS Security** — SPF and DMARC record detection to identify email spoofing risk
- **TLS Inspection** — Certificate validity, issuer, and expiration date via live handshake
- **HTTP Header Audit** — Checks for `Strict-Transport-Security` and `Content-Security-Policy`
- **Animated UI** — Smooth caret input, theme toggle with view transitions, scroll-reveal text, spring physics
- **Dark / Light Mode** — Animated full-page theme switching via Skiper UI
- **Legal & Ethical Footer** — Terms of Service, Ethical Use Policy, Disclaimer, and Responsible Disclosure built in

---

## 🏗️ Architecture

```
threat-intel-scraper/
│
├── server.py              # Flask API backend (POST /api/scan)
├── requirements.txt       # Python dependencies
├── app.py                 # (legacy Streamlit app — kept for reference)
│
├── scraper/               # Python intelligence modules
│   ├── whois_lookup.py    # WHOIS domain registration data
│   ├── dns_lookup.py      # DNS record resolution (A, MX, TXT, NS, AAAA)
│   ├── tls_lookup.py      # TLS certificate inspection
│   ├── http_headers.py    # HTTP security header retrieval
│   └── scoring.py         # Heuristic trust score engine
│
└── frontend/              # React + Vite web application
    ├── src/
    │   ├── App.tsx                    # Main application layout & scan logic
    │   ├── index.css                  # Tailwind v4 + CSS variables (dark/light)
    │   ├── main.tsx                   # React entry point + ThemeProvider
    │   └── components/
    │       ├── Skiper26.tsx           # Theme toggle (view-transition animation)
    │       ├── Skiper31.tsx           # Scroll-reveal text (Lenis + Framer Motion)
    │       ├── Skiper58.tsx           # Text roll navigation
    │       ├── Skiper106.tsx          # Smooth caret input (spring physics)
    │       └── Footer.tsx             # Legal, T&C, ethics accordion footer
    ├── tailwind.config.js
    └── postcss.config.js
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+**
- **Node.js 18+**

### 1. Clone the repository

```bash
git clone https://github.com/ajeypandey/threat-intel-scraper.git
cd threat-intel-scraper
```

### 2. Set up the Python backend

```bash
pip install -r requirements.txt
```

### 3. Start the Flask API server

```bash
python server.py
```

The API will be available at `http://127.0.0.1:5000`.

### 4. Set up and start the React frontend

```bash
cd frontend
npm install
npm run dev
```

The UI will be available at `http://localhost:5173`.

> Make sure **both** the Flask backend and the Vite dev server are running simultaneously.

---

## 🧠 How Scoring Works

The engine computes a **Trust Score** by starting at 100 and deducting points for risk signals:

| Signal | Deduction | Reason |
|---|---|---|
| Domain < 30 days old | −40 | Newly registered domains are a common phishing indicator |
| Domain 30–180 days old | −20 | Relatively new, treat with caution |
| WHOIS unavailable | −10 | Cannot verify registration data |
| No SPF record | −10 | Email spoofing risk |
| No DMARC record | −10 | No email policy enforcement |
| Invalid / missing TLS | −25 | No HTTPS — critical trust failure |
| No HSTS header | −10 | Users can be downgraded to HTTP |
| No CSP header | −5 | Increased XSS exposure (minor; many trusted sites omit this) |

**Final Score = 100 − total deductions**, clamped to [0, 100].

| Score Range | Verdict |
|---|---|
| 85–100 | ✅ Trusted |
| 60–84 | 🟡 Low Risk |
| 40–59 | 🟠 Moderate Risk |
| 0–39 | 🔴 High Risk |

---

## 🎨 UI Stack

| Technology | Purpose |
|---|---|
| React 18 + TypeScript | Frontend framework |
| Vite 8 | Build tool / dev server |
| Tailwind CSS v4 | Utility styling |
| Framer Motion | Animations & transitions |
| next-themes | Dark/light mode management |
| Lenis | Smooth scrolling |
| Skiper UI | Component animation library |

---

## ⚠️ Ethical Use

This tool is intended **strictly for authorized security research, threat hunting, and education**. Only scan domains you own or have explicit written permission to investigate.

Misuse of this tool may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or equivalent laws in your jurisdiction. See the in-app footer for full Terms of Service, Ethical Use Policy, and Responsible Disclosure guidelines.

---

## � Deployment

The app is prepared for a simple cloud deployment setup:

- Backend: Flask API served by Gunicorn via the included Procfile
- Frontend: Vite static build generated in frontend/dist
- Config files: render.yaml, .env.example, frontend/.env.example, frontend/.env.production.example

### Render example

1. Create two services:
   - one Python web service for the API
   - one static site for the frontend build
2. Point the frontend service to the backend URL in the build env var `VITE_API_URL`
3. Set `CORS_ORIGINS` on the backend to the frontend origin

### Local production-style test

```bash
cd frontend
npm install
npm run build
```

Then serve the generated static files from frontend/dist and run the backend with:

```bash
python server.py
```

## �📄 License

MIT License — free to use, modify, and distribute with attribution.

---

*Built with ❤️ by Ajey Pandey*
