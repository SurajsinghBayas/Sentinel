# 🛡️ ANBU Sentinel v2
**AI-Powered Network Anomaly Detection & Incident Intelligence System**

---

## Stack
| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + TypeScript + ShadCN UI + Recharts + Framer Motion |
| Backend | Python 3.11 + FastAPI + Uvicorn |
| AI Narration | **AWS Bedrock** (Claude 3.5 Sonnet) |
| PDF Reports | `@react-pdf/renderer` |
| Auth | JWT (HS256) — access + refresh tokens, bcrypt |
| Real-time | WebSocket log streaming |
| Detection | Rule engine + scikit-learn Isolation Forest |

---

## Quick Start

### Backend
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # Add your AWS keys + JWT secrets
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

### Sample Logs
Available in `sample_logs/`:
- `apache_access.log` — Brute force, SQLi, DDoS, XSS
- `syslog.log` — SSH brute force, port scan
- `zeek_conn.csv` — Network anomalies, exfiltration
- `nginx_error.log` — Directory traversal

---

## Features
- 🔐 **JWT Auth** — Login/Signup with access + refresh tokens
- 📡 **Live Log Stream** — WebSocket real-time ingestion  
- 📤 **Log Upload** — Apache, Nginx, Syslog, Zeek CSV
- 🧠 **AI Narration** — AWS Bedrock Claude 3.5 Sonnet
- 📊 **Dashboard** — Recharts area, pie, bar charts  
- 🔍 **Detections** — Expandable threat cards with AI analysis  
- ⏱️ **Timeline** — Chronological attack view
- 📄 **PDF Reports** — Branded incident reports via @react-pdf/renderer

---

## AWS Bedrock Setup
Add to `backend/.env`:
```
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
```
Enable Bedrock model access in AWS Console → Bedrock → Model access.

> **Without AWS keys**: The system uses intelligent template-based fallback narration automatically.

API Docs: http://localhost:8000/api/docs
