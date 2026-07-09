# AI-Powered Security Alert Triage & Investigation Assistant

An intelligent security operations platform that uses ML to classify and cluster security alerts, and a RAG-powered investigation assistant to help analysts investigate cases using MITRE ATT&CK threat intelligence.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Next.js 15 Dashboard                                   │
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

**Backend:** Python 3.11+, FastAPI, scikit-learn, XGBoost, LangChain, FAISS, OpenAI/Google Gemini
**Frontend:** Next.js 15, TypeScript, Tailwind CSS, Recharts
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
cp .env.example .env
# Edit .env and add your OpenAI or Google API key
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

### 4. Ingest MITRE ATT&CK Knowledge Base

```bash
python -m rag.ingest
```

This scrapes MITRE ATT&CK technique pages, chunks them, generates embeddings, and stores them in a local FAISS vector store.

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
├── backend/
│   ├── main.py              # FastAPI application
│   ├── requirements.txt
│   ├── ml/
│   │   ├── classifier.py    # Alert severity & type classification
│   │   ├── anomaly.py       # Isolation Forest anomaly detection
│   │   ├── clustering.py    # DBSCAN alert clustering into cases
│   │   └── train.py         # Training pipeline (download + train)
│   ├── rag/
│   │   ├── engine.py        # LangChain RAG investigation engine
│   │   ├── ingest.py        # MITRE ATT&CK data ingestion
│   │   └── prompts.py       # Prompt templates
│   ├── models/
│   │   └── schemas.py       # Pydantic data models
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
│   │   ├── alerts/page.tsx  # Alert queue
│   │   └── cases/
│   │       ├── page.tsx     # Cases list
│   │       └── [id]/page.tsx # Case detail + AI chat
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

- **ML-Powered Alert Classification**: Random Forest model trained on UNSW-NB15 classifies alerts by attack type (DoS, Exploits, Reconnaissance, etc.) and severity
- **Anomaly Detection**: Isolation Forest flags unusual patterns that don't match known attack categories
- **Smart Case Generation**: DBSCAN clustering groups related alerts into investigation cases based on source IP, attack type, and temporal proximity
- **RAG Investigation Assistant**: LangChain-powered chatbot grounded in MITRE ATT&CK data helps analysts investigate cases with context-aware responses
- **MITRE ATT&CK Mapping**: Every classified alert is mapped to relevant ATT&CK techniques with mitigation recommendations
- **Real-time Dashboard**: Next.js frontend with alert queue, case management, investigation chat, and metrics

## Resume Bullet Points

After building this, you can add lines like:
- Built an AI-powered security alert triage platform with ML classification (94%+ accuracy on UNSW-NB15), anomaly detection, and automated case generation via DBSCAN clustering
- Developed a RAG-based investigation assistant using LangChain and FAISS over MITRE ATT&CK framework, enabling analysts to query threat intelligence in natural language
- Designed a full-stack SOC analyst dashboard (Next.js, FastAPI) with real-time alert queue, case management, and MITRE ATT&CK technique mapping

## License

MIT
