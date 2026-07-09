"""Alert clustering to group related alerts into investigation cases.

Uses DBSCAN to cluster alerts based on:
- Source/destination IP similarity
- Attack category
- Temporal proximity
- Network behavior features
"""

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from datetime import datetime
import hashlib
import uuid


class AlertClusterer:
    """Groups related alerts into investigation cases using DBSCAN."""

    def __init__(self, eps: float = 0.5, min_samples: int = 3):
        """
        Args:
            eps: DBSCAN neighborhood radius
            min_samples: Minimum alerts to form a case cluster
        """
        self.eps = eps
        self.min_samples = min_samples

    def cluster_alerts(self, alerts: list[dict]) -> list[dict]:
        """Cluster alerts into investigation cases.

        Args:
            alerts: List of classified alert dicts with fields:
                - id, source_ip, dest_ip, attack_category,
                  severity, timestamp, sbytes, dbytes, rate, etc.

        Returns:
            List of case dicts, each containing grouped alert IDs
        """
        if len(alerts) < self.min_samples:
            # Not enough alerts to cluster — put them all in one case
            if alerts:
                return [self._make_case(alerts, cluster_id=0)]
            return []

        # Build feature matrix for clustering
        feature_matrix = self._build_features(alerts)

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(feature_matrix)

        # Run DBSCAN
        db = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="euclidean")
        labels = db.fit_predict(X_scaled)

        # Group alerts by cluster label
        clusters = defaultdict(list)
        noise_alerts = []

        for alert, label in zip(alerts, labels):
            if label == -1:
                noise_alerts.append(alert)
            else:
                clusters[label].append(alert)

        # Build cases from clusters
        cases = []
        for cluster_id, cluster_alerts in clusters.items():
            cases.append(self._make_case(cluster_alerts, cluster_id))

        # Group remaining noise alerts by attack category
        if noise_alerts:
            noise_by_cat = defaultdict(list)
            for alert in noise_alerts:
                cat = alert.get("attack_category", "Normal")
                noise_by_cat[cat].append(alert)

            for cat, cat_alerts in noise_by_cat.items():
                cases.append(self._make_case(cat_alerts, cluster_id=f"noise-{cat}"))

        return sorted(cases, key=lambda c: self._severity_rank(c["severity"]), reverse=True)

    def _build_features(self, alerts: list[dict]) -> np.ndarray:
        """Build a numeric feature matrix from alerts for clustering."""
        features = []
        for alert in alerts:
            # IP hash (group same source IPs together)
            src_hash = int(hashlib.md5(
                alert.get("source_ip", "0.0.0.0").encode()
            ).hexdigest()[:8], 16) / 1e9

            dst_hash = int(hashlib.md5(
                alert.get("dest_ip", "0.0.0.0").encode()
            ).hexdigest()[:8], 16) / 1e9

            # Attack category as numeric
            attack_cats = [
                "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
                "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms",
            ]
            cat = alert.get("attack_category", "Normal")
            cat_num = attack_cats.index(cat) if cat in attack_cats else 0

            # Severity as numeric
            severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            sev_num = severity_map.get(alert.get("severity", "info"), 0)

            # Timestamp as hour of day (temporal clustering)
            ts = alert.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    ts = datetime.now()
            elif not isinstance(ts, datetime):
                ts = datetime.now()
            hour = ts.hour + ts.minute / 60.0

            # Network features
            sbytes = alert.get("sbytes", 0)
            dbytes = alert.get("dbytes", 0)
            rate = alert.get("rate", 0)

            features.append([
                src_hash, dst_hash, cat_num, sev_num,
                hour, sbytes, dbytes, rate,
            ])

        return np.array(features, dtype=np.float64)

    def _make_case(self, alerts: list[dict], cluster_id) -> dict:
        """Build a case dict from a cluster of alerts."""
        case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"

        # Determine primary attack (most common non-Normal category)
        attack_counts = defaultdict(int)
        for a in alerts:
            cat = a.get("attack_category", "Normal")
            attack_counts[cat] += 1

        # Prefer non-Normal attacks
        non_normal = {k: v for k, v in attack_counts.items() if k != "Normal"}
        if non_normal:
            primary_attack = max(non_normal, key=non_normal.get)
        else:
            primary_attack = "Normal"

        # Determine case severity (highest alert severity)
        severity_order = ["info", "low", "medium", "high", "critical"]
        severities = [a.get("severity", "info") for a in alerts]
        case_severity = max(severities, key=lambda s: severity_order.index(s) if s in severity_order else 0)

        # Collect unique IPs and MITRE techniques
        source_ips = list(set(a.get("source_ip", "0.0.0.0") for a in alerts))
        mitre = list(set(
            t for a in alerts
            for t in a.get("mitre_techniques", [])
        ))

        # Generate title
        title = f"{primary_attack} activity from {len(source_ips)} source(s)"
        if primary_attack == "Normal":
            title = f"Suspicious traffic cluster ({len(alerts)} alerts)"

        # Build timeline
        timeline = []
        for a in sorted(alerts, key=lambda x: str(x.get("timestamp", ""))):
            timeline.append({
                "timestamp": str(a.get("timestamp", "")),
                "alert_id": a.get("id", ""),
                "event": f"{a.get('attack_category', 'Unknown')} - {a.get('severity', 'info')}",
                "source_ip": a.get("source_ip", ""),
                "dest_ip": a.get("dest_ip", ""),
            })

        now = datetime.now().isoformat()
        return {
            "id": case_id,
            "title": title,
            "status": "open",
            "severity": case_severity,
            "alert_ids": [a.get("id", "") for a in alerts],
            "alert_count": len(alerts),
            "primary_attack": primary_attack,
            "mitre_techniques": mitre,
            "source_ips": source_ips,
            "created_at": now,
            "updated_at": now,
            "summary": f"Cluster of {len(alerts)} related alerts, primarily {primary_attack} activity.",
            "timeline": timeline,
        }

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
