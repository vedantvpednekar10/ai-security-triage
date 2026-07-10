# AI-Powered Security Alert Triage & Investigation Assistant

An AI-powered SOC analyst workbench: ML classifies and clusters security alerts, and a RAG-powered investigation assistant helps analysts investigate them using real MITRE ATT&CK threat intelligence.

> **Scope note:** this is a portfolio/demo project built on the public UNSW-NB15 benchmark dataset — it's a proof-of-concept analyst workbench, not a production sensor connected to live network traffic. See [Known Limitations](#known-limitations) below.

## Demo

[Watch the demo](./Demo.mp4)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Next.js 16 Dashboard                                    │
│  ┌───────────┐ ┌──────────┐ ┌─────────┐ ┌───────────┐  │
│  │Alert Queue│ │Case View │ │AI Chat  │ │ Metrics   │  │
│  └───────────┘ └──────────┘ └─────────┘ └───────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │ REST API
┌────────────────────────┴────────────────────────────────┐
│  FastAPI Backend                                        │
│  ┌────────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │ ML Pipeline    │  │ RAG Engine  │  │ Case Manager │ │
│  │ - Classifier   │  │ - LangChain │  │ - CRUD       │ │
│  │ - Anomaly Det. │  │ - FAISS     │  │ - Clustering │ │
│  │ - Clustering   │  │ - ATT&CK KB │  │ - Timeline   │ │
│  └────────────────┘  └─────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
         │                    │
    UNSW-NB15            MITRE ATT&CK
    Dataset              Knowledge Base
```

## Tech Stack

**Backend:** Python 3.11+, FastAPI, scikit-learn (Random Forest + Isolation Forest), LangChain, FAISS, Google Gemini (`gemini-2.5-flash` + `gemini-embedding-001`)
**Frontend:** Next.js 16, TypeScript, Tailwind CSS, Recharts
**Data:** UNSW-NB15 dataset, MITRE ATT&CK framework

## Quick Start

### 1. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env     # Windows: copy .env.example .env
# Edit .env and add your Google Gemini API key (https://aistudio.google.com/app/apikey)
```

### 3. Download Data & Train Models

```bash
# Downloads UNSW-NB15 dataset and trains the ML models
python -m ml.train
```

This will:
- Download the UNSW-NB15 training/testing datasets
- Preprocess features (encode categoricals, normalize numerics)
- Train a Random Forest classifier for attack type classification
- Train an Isolation Forest for anomaly detection
- Save trained models to `backend/trained_models/`

> Pre-trained models are already committed to this repo under `backend/trained_models/` and `backend/vectorstore/`, so you can skip straight to step 5 if you just want to run the app as-is.

### 4. Ingest MITRE ATT&CK Knowledge Base

```bash
python -m rag.ingest
```

This downloads MITRE ATT&CK technique data, chunks it, generates embeddings, and stores them in a local FAISS vector store.

### 5. Start the Backend

```bash
uvicorn main:app --reload --port 8000
```

API docs available at http://localhost:8000/docs

### 6. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Dashboard available at http://localhost:3000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List all alerts with filters |
| POST | `/api/alerts/classify` | Classify a single alert |
| POST | `/api/alerts/bulk-classify` | Classify a batch of alerts |
| GET | `/api/cases` | List investigation cases |
| GET | `/api/cases/{id}` | Get case details with timeline |
| POST | `/api/cases/generate` | Auto-cluster alerts into cases |
| POST | `/api/investigate` | Ask the RAG assistant a question |
| GET | `/api/metrics` | Dashboard metrics & stats |
| GET | `/api/mitre/techniques` | List MITRE ATT&CK techniques |

## Project Structure

```
ai-security-triage/
├── demo.mp4                 # Walkthrough demo
├── backend/
│   ├── main.py              # FastAPI application
│   ├── requirements.txt
│   ├── ml/
│   │   ├── classifier.py    # Alert type classification (Random Forest)
│   │   ├── anomaly.py       # Isolation Forest anomaly detection
│   │   ├── clustering.py    # DBSCAN alert clustering into cases
│   │   └── train.py         # Training pipeline (download + train)
│   ├── rag/
│   │   ├── engine.py        # LangChain RAG investigation engine
│   │   ├── ingest.py        # MITRE ATT&CK data ingestion
│   │   └── prompts.py       # Prompt templates
│   ├── models/
│   │   └── schemas.py       # Pydantic data models
│   ├── trained_models/      # Pre-trained classifier, anomaly detector, encoders
│   ├── vectorstore/         # Pre-built FAISS index over MITRE ATT&CK
│   ├── data/
│   │   ├── sample_alerts.json
│   │   └── mitre_techniques.json
│   └── utils/
│       └── mitre_mapper.py  # Map predictions to MITRE techniques
├── frontend/
│   ├── package.json
│   ├── next.config.mjs
│   ├── tailwind.config.ts
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx         # Dashboard home
│   │   ├── alerts/page.tsx  # Alert queue + investigation chat
│   │   └── cases/
│   │       ├── page.tsx     # Cases list
│   │       └── [id]/page.tsx # Case detail
│   ├── components/
│   │   ├── Sidebar.tsx
│   │   ├── AlertQueue.tsx
│   │   ├── CaseView.tsx
│   │   ├── InvestigationChat.tsx
│   │   ├── MetricsDashboard.tsx
│   │   └── SeverityBadge.tsx
│   └── lib/
│       └── api.ts           # API client
└── README.md
```

## Key Features

- **ML-Powered Alert Classification**: Random Forest classifier trained on UNSW-NB15 (175K records) classifies alerts by attack type (DoS, Exploits, Reconnaissance, Backdoor, Worms, etc.)
- **Anomaly Detection**: Isolation Forest flags unusual patterns that don't match known attack categories
- **Smart Case Generation**: DBSCAN clustering groups related alerts into investigation cases based on source IP, attack type, and temporal proximity
- **RAG Investigation Assistant**: LangChain-powered chatbot grounded in real MITRE ATT&CK documentation (via a FAISS vector store) helps analysts investigate alerts with context-aware, technique-cited responses — not generic LLM guesses
- **MITRE ATT&CK Mapping**: Every classified alert is mapped to relevant ATT&CK techniques
- **Real-time Dashboard**: Next.js frontend with alert queue, case management, investigation chat, and metrics

## Model Performance

Trained on the UNSW-NB15 benchmark (175,341 training records, 82,332 test records, 10 attack categories):

- **Overall test accuracy: ~66%**
- Strong performance on high-volume/well-separated classes: Generic (98% F1), Normal (73% F1), Reconnaissance (82% F1)
- Weaker precision on rare classes (Backdoor, Shellcode, Worms — each under 1.5% of training data), though the model was deliberately tuned to **favor recall over precision on these critical categories** (e.g. 84-96% recall on Worms/Shellcode) — in a SOC triage context, missing a real backdoor is worse than an analyst dismissing a false alarm.
- Model size was reduced from 259MB to ~19MB (constrained tree depth/count) after identifying overfitting (82% train vs. 68% test accuracy on the original config) — this also improved generalization on the rare, high-severity classes.

Not claiming production-grade accuracy here — this reflects real, honest numbers on a known-imbalanced public dataset, with a documented rationale for the precision/recall tradeoff.

## Known Limitations

- **Not a live sensor**: alerts come from a static sample set or the `/api/alerts/classify` endpoint — there's no packet capture or live traffic ingestion.
- **Fixed feature schema**: the classifier requires input in UNSW-NB15's exact 37-feature flow-record format (packet counts, TCP timing stats, etc.). It cannot ingest arbitrary raw network logs or PCAPs without a dedicated feature-extraction layer.
- **Class imbalance**: rare attack types (Worms, Shellcode, Backdoor) are underrepresented in the training data, which is a known property of most public intrusion-detection datasets, not specific to this implementation.

## Security Notes

- The original `next@15.0.0` dependency shipped with a critical RCE vulnerability (CVE-2025-66478); this project has been upgraded to a patched Next.js version.
- API keys are loaded from `.env` (gitignored) and never committed.

## Resume Bullet Points

- Built an AI-powered SOC alert triage platform: ML-based alert classification (Random Forest on UNSW-NB15, 175K records) and anomaly detection (Isolation Forest), with automated case generation via DBSCAN clustering
- Developed a RAG-based investigation assistant (LangChain + FAISS + Gemini) grounded in the MITRE ATT&CK framework, enabling analysts to query threat intelligence in natural language with technique-cited responses
- Identified and corrected classifier overfitting (82% train vs. 68% test accuracy) by constraining model complexity, cutting model size by 93% (259MB → 19MB) while improving recall on critical/rare attack categories
- Found and patched a critical (CVSS 10.0) remote code execution vulnerability (CVE-2025-66478) in the frontend's Next.js dependency before deployment
- Designed a full-stack SOC analyst dashboard (Next.js, FastAPI) with real-time alert queue, case management, and MITRE ATT&CK technique mapping

## License

MIT