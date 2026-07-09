"""Security Alert Triage API

FastAPI application providing endpoints for alert classification,
case management, and AI-powered investigation.
"""

import os
import json
import uuid
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from models.schemas import (
    Alert, AlertClassifyRequest, BulkClassifyRequest,
    Case, CaseDetail, CaseStatus, Severity,
    InvestigateRequest, InvestigateResponse,
    DashboardMetrics, AlertFeatures,
)
from ml.classifier import AlertClassifier
from ml.anomaly import AnomalyDetector
from ml.clustering import AlertClusterer
from rag.engine import InvestigationEngine
from utils.mitre_mapper import map_attack_to_mitre, get_mitigations, get_all_techniques


# ── In-memory data stores (swap for a real DB in production) ──

alerts_db: dict[str, dict] = {}
cases_db: dict[str, dict] = {}

# ── ML components (loaded at startup) ──

classifier: Optional[AlertClassifier] = None
anomaly_detector: Optional[AnomalyDetector] = None
clusterer: Optional[AlertClusterer] = None
investigation_engine: Optional[InvestigationEngine] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML models and sample data on startup."""
    global classifier, anomaly_detector, clusterer, investigation_engine

    print("Loading ML models...")
    classifier = AlertClassifier()
    anomaly_detector = AnomalyDetector()
    clusterer = AlertClusterer(eps=0.8, min_samples=2)
    investigation_engine = InvestigationEngine()

    # Load sample alerts
    sample_path = os.path.join(os.path.dirname(__file__), "data", "sample_alerts.json")
    if os.path.exists(sample_path):
        with open(sample_path, "r") as f:
            samples = json.load(f)
        for alert in samples:
            alerts_db[alert["id"]] = alert
        print(f"Loaded {len(samples)} sample alerts.")

    yield
    print("Shutting down...")


app = FastAPI(
    title="Security Alert Triage API",
    description="AI-powered security alert classification, case management, and investigation",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_URL", "http://localhost:3000"),
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Alert Endpoints ──


@app.get("/api/alerts", response_model=list[dict])
async def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by attack category"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List all alerts with optional filtering."""
    alerts = list(alerts_db.values())

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if category:
        alerts = [a for a in alerts if a.get("attack_category") == category]

    # Sort by timestamp descending (newest first)
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    return alerts[offset:offset + limit]


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a single alert by ID."""
    alert = alerts_db.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/api/alerts/classify")
async def classify_alert(request: AlertClassifyRequest):
    """Classify a single alert using the ML pipeline."""
    features_dict = request.features.model_dump()

    # Step 1: Classify attack type
    classification = classifier.classify(features_dict)

    # Step 2: Check for anomalies
    anomaly = anomaly_detector.detect(features_dict)

    # Step 3: Map to MITRE ATT&CK
    attack_cat = classification["attack_category"]
    mitre = map_attack_to_mitre(attack_cat)
    mitigations = get_mitigations(attack_cat)

    # Build alert
    alert_id = f"ALERT-{str(uuid.uuid4())[:8].upper()}"
    alert = {
        "id": alert_id,
        "timestamp": datetime.now().isoformat(),
        "source_ip": request.source_ip,
        "dest_ip": request.dest_ip,
        "source_port": request.source_port,
        "dest_port": request.dest_port,
        "attack_category": attack_cat,
        "severity": classification["severity"],
        "confidence": classification["confidence"],
        "is_anomaly": anomaly["is_anomaly"],
        "anomaly_score": anomaly["anomaly_score"],
        "mitre_techniques": [t["id"] for t in mitre],
        "mitre_details": mitre,
        "mitigations": mitigations,
        "probabilities": classification["probabilities"],
        "description": f"{attack_cat} activity detected from {request.source_ip}",
        "features": features_dict,
    }

    # Store in DB
    alerts_db[alert_id] = alert

    return alert


@app.post("/api/alerts/bulk-classify")
async def bulk_classify(request: BulkClassifyRequest):
    """Classify a batch of alerts."""
    results = []
    for alert_req in request.alerts:
        features_dict = alert_req.features.model_dump()
        classification = classifier.classify(features_dict)
        anomaly = anomaly_detector.detect(features_dict)
        attack_cat = classification["attack_category"]
        mitre = map_attack_to_mitre(attack_cat)

        alert_id = f"ALERT-{str(uuid.uuid4())[:8].upper()}"
        alert = {
            "id": alert_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": alert_req.source_ip,
            "dest_ip": alert_req.dest_ip,
            "source_port": alert_req.source_port,
            "dest_port": alert_req.dest_port,
            "attack_category": attack_cat,
            "severity": classification["severity"],
            "confidence": classification["confidence"],
            "is_anomaly": anomaly["is_anomaly"],
            "mitre_techniques": [t["id"] for t in mitre],
            "description": f"{attack_cat} activity detected",
        }
        alerts_db[alert_id] = alert
        results.append(alert)

    return {"classified": len(results), "alerts": results}


# ── Case Endpoints ──


@app.get("/api/cases", response_model=list[dict])
async def list_cases(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List all investigation cases."""
    cases = list(cases_db.values())

    if status:
        cases = [c for c in cases if c.get("status") == status]
    if severity:
        cases = [c for c in cases if c.get("severity") == severity]

    cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    return cases


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    """Get case details including alerts and timeline."""
    case = cases_db.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Attach full alert data
    case_alerts = [
        alerts_db[aid] for aid in case.get("alert_ids", [])
        if aid in alerts_db
    ]
    case["alerts"] = case_alerts
    return case


@app.post("/api/cases/generate")
async def generate_cases():
    """Auto-cluster existing alerts into investigation cases."""
    alert_list = list(alerts_db.values())

    if not alert_list:
        return {"message": "No alerts to cluster", "cases": []}

    cases = clusterer.cluster_alerts(alert_list)

    # Store cases and update alerts with case IDs
    for case in cases:
        cases_db[case["id"]] = case
        for alert_id in case.get("alert_ids", []):
            if alert_id in alerts_db:
                alerts_db[alert_id]["case_id"] = case["id"]

    return {"generated": len(cases), "cases": cases}


@app.patch("/api/cases/{case_id}/status")
async def update_case_status(case_id: str, status: str):
    """Update a case's status."""
    case = cases_db.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    valid = ["open", "investigating", "resolved", "false_positive"]
    if status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")

    case["status"] = status
    case["updated_at"] = datetime.now().isoformat()
    return case


# ── Investigation Endpoints ──


@app.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(request: InvestigateRequest):
    """Ask the AI investigation assistant a question."""
    # Build context from case/alert if provided
    alert_context = ""
    if request.case_id and request.case_id in cases_db:
        case = cases_db[request.case_id]
        alert_context = (
            f"Case: {case['title']}\n"
            f"Primary Attack: {case['primary_attack']}\n"
            f"Severity: {case['severity']}\n"
            f"Alert Count: {case['alert_count']}\n"
            f"Source IPs: {', '.join(case.get('source_ips', []))}\n"
            f"MITRE Techniques: {', '.join(case.get('mitre_techniques', []))}"
        )
    elif request.alert_id and request.alert_id in alerts_db:
        alert = alerts_db[request.alert_id]
        alert_context = (
            f"Alert: {alert.get('description', '')}\n"
            f"Attack Category: {alert.get('attack_category', '')}\n"
            f"Severity: {alert.get('severity', '')}\n"
            f"Source IP: {alert.get('source_ip', '')}\n"
            f"Dest IP: {alert.get('dest_ip', '')}\n"
            f"MITRE Techniques: {', '.join(alert.get('mitre_techniques', []))}"
        )

    result = investigation_engine.investigate(request.question, alert_context)
    return InvestigateResponse(**result)


# ── MITRE Endpoints ──


@app.get("/api/mitre/techniques")
async def list_mitre_techniques():
    """List all MITRE ATT&CK techniques in our mapping."""
    # Try loading the full techniques JSON first
    techniques_path = os.path.join(os.path.dirname(__file__), "data", "mitre_techniques.json")
    if os.path.exists(techniques_path):
        with open(techniques_path, "r") as f:
            return json.load(f)
    return get_all_techniques()


# ── Metrics Endpoints ──


@app.get("/api/metrics", response_model=DashboardMetrics)
async def get_metrics():
    """Get dashboard metrics and statistics."""
    alerts = list(alerts_db.values())
    cases = list(cases_db.values())

    # Count by severity
    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    technique_counts = defaultdict(int)

    total_confidence = 0.0
    for a in alerts:
        severity_counts[a.get("severity", "info")] += 1
        category_counts[a.get("attack_category", "Normal")] += 1
        ip_counts[a.get("source_ip", "unknown")] += 1
        total_confidence += a.get("confidence", 0)
        for t in a.get("mitre_techniques", []):
            technique_counts[t] += 1

    # Case stats
    open_cases = sum(1 for c in cases if c.get("status") in ["open", "investigating"])
    resolved = sum(1 for c in cases if c.get("status") == "resolved")
    fp = sum(1 for c in cases if c.get("status") == "false_positive")
    fp_rate = fp / max(len(cases), 1)

    # Top source IPs
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Alerts over time (group by hour)
    time_buckets = defaultdict(int)
    for a in alerts:
        ts = a.get("timestamp", "")
        if ts:
            hour = ts[:13]  # YYYY-MM-DDTHH
            time_buckets[hour] += 1

    alerts_over_time = [
        {"time": k, "count": v}
        for k, v in sorted(time_buckets.items())
    ]

    return DashboardMetrics(
        total_alerts=len(alerts),
        critical_alerts=severity_counts.get("critical", 0),
        high_alerts=severity_counts.get("high", 0),
        open_cases=open_cases,
        resolved_cases=resolved,
        false_positive_rate=round(fp_rate, 3),
        avg_classification_confidence=round(total_confidence / max(len(alerts), 1), 3),
        alerts_by_category=dict(category_counts),
        alerts_by_severity=dict(severity_counts),
        alerts_over_time=alerts_over_time,
        top_source_ips=[{"ip": ip, "count": c} for ip, c in top_ips],
        top_mitre_techniques=[{"technique": t, "count": c} for t, c in top_techniques],
    )


# ── Health ──


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "classifier_loaded": classifier.model is not None if classifier else False,
        "anomaly_detector_loaded": anomaly_detector.model is not None if anomaly_detector else False,
        "rag_initialized": investigation_engine._initialized if investigation_engine else False,
        "alerts_count": len(alerts_db),
        "cases_count": len(cases_db),
    }
