"""Pydantic schemas for the Security Alert Triage system."""

from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(str, Enum):
    NORMAL = "Normal"
    ANALYSIS = "Analysis"
    BACKDOOR = "Backdoor"
    DOS = "DoS"
    EXPLOITS = "Exploits"
    FUZZERS = "Fuzzers"
    GENERIC = "Generic"
    RECONNAISSANCE = "Reconnaissance"
    SHELLCODE = "Shellcode"
    WORMS = "Worms"


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ── Alert Models ──


class AlertFeatures(BaseModel):
    """Raw network features from UNSW-NB15 format."""
    dur: float = Field(description="Record total duration")
    proto: str = Field(default="tcp", description="Protocol (tcp, udp, etc.)")
    service: str = Field(default="-", description="Service type (http, ftp, etc.)")
    state: str = Field(default="FIN", description="Connection state")
    spkts: int = Field(default=0, description="Source-to-dest packet count")
    dpkts: int = Field(default=0, description="Dest-to-source packet count")
    sbytes: int = Field(default=0, description="Source-to-dest bytes")
    dbytes: int = Field(default=0, description="Dest-to-source bytes")
    rate: float = Field(default=0.0, description="Packets per second")
    sttl: int = Field(default=64, description="Source TTL")
    dttl: int = Field(default=64, description="Dest TTL")
    sload: float = Field(default=0.0, description="Source bits per second")
    dload: float = Field(default=0.0, description="Dest bits per second")
    sloss: int = Field(default=0, description="Source packets retransmitted/dropped")
    dloss: int = Field(default=0, description="Dest packets retransmitted/dropped")
    sinpkt: float = Field(default=0.0, description="Source inter-packet arrival time (ms)")
    dinpkt: float = Field(default=0.0, description="Dest inter-packet arrival time (ms)")
    sjit: float = Field(default=0.0, description="Source jitter (ms)")
    djit: float = Field(default=0.0, description="Dest jitter (ms)")
    swin: int = Field(default=0, description="Source TCP window size")
    stcpb: int = Field(default=0, description="Source TCP base sequence number")
    dtcpb: int = Field(default=0, description="Dest TCP base sequence number")
    dwin: int = Field(default=0, description="Dest TCP window size")
    tcprtt: float = Field(default=0.0, description="TCP round-trip time")
    synack: float = Field(default=0.0, description="SYN-ACK round-trip time")
    ackdat: float = Field(default=0.0, description="ACK-data round-trip time")
    smean: int = Field(default=0, description="Mean of source packet size")
    dmean: int = Field(default=0, description="Mean of dest packet size")
    trans_depth: int = Field(default=0, description="Pipelined depth of connection")
    response_body_len: int = Field(default=0, description="HTTP response body length")
    ct_srv_src: int = Field(default=0, description="Connections to same service from src")
    ct_state_ttl: int = Field(default=0, description="Connections of same state and TTL")
    ct_dst_ltm: int = Field(default=0, description="Connections to same dest in last 100")
    ct_src_dport_ltm: int = Field(default=0, description="Connections from src to same dest port")
    ct_dst_sport_ltm: int = Field(default=0, description="Connections to dest from same src port")
    ct_dst_src_ltm: int = Field(default=0, description="Connections between src and dest in last 100")
    is_ftp_login: int = Field(default=0, description="1 if FTP session had login")
    ct_ftp_cmd: int = Field(default=0, description="Number of FTP commands in session")
    ct_flw_http_mthd: int = Field(default=0, description="Number of HTTP methods in flow")
    ct_src_ltm: int = Field(default=0, description="Connections from same src in last 100")
    ct_srv_dst: int = Field(default=0, description="Connections to same service at dest")
    is_sm_ips_ports: int = Field(default=0, description="1 if src=dst IP and port")


class Alert(BaseModel):
    """A classified security alert."""
    id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    source_port: int = 0
    dest_port: int = 0
    attack_category: AttackCategory = AttackCategory.NORMAL
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0, le=1)
    is_anomaly: bool = False
    mitre_techniques: list[str] = []
    description: str = ""
    case_id: Optional[str] = None
    features: Optional[AlertFeatures] = None


class AlertClassifyRequest(BaseModel):
    """Request to classify alert features."""
    features: AlertFeatures
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    source_port: int = 0
    dest_port: int = 0


class BulkClassifyRequest(BaseModel):
    """Request to classify multiple alerts."""
    alerts: list[AlertClassifyRequest]


# ── Case Models ──


class Case(BaseModel):
    """An investigation case grouping related alerts."""
    id: str
    title: str
    status: CaseStatus = CaseStatus.OPEN
    severity: Severity = Severity.MEDIUM
    alert_ids: list[str] = []
    alert_count: int = 0
    primary_attack: AttackCategory = AttackCategory.NORMAL
    mitre_techniques: list[str] = []
    source_ips: list[str] = []
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    summary: str = ""


class CaseDetail(Case):
    """Case with full alert data and timeline."""
    alerts: list[Alert] = []
    timeline: list[dict] = []


# ── Investigation Models ──


class InvestigateRequest(BaseModel):
    """Ask the AI investigation assistant a question."""
    question: str
    case_id: Optional[str] = None
    alert_id: Optional[str] = None


class InvestigateResponse(BaseModel):
    """Response from the investigation assistant."""
    answer: str
    sources: list[dict] = []
    mitre_techniques: list[dict] = []
    suggested_actions: list[str] = []


# ── Metrics Models ──


class DashboardMetrics(BaseModel):
    """Dashboard overview metrics."""
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    open_cases: int = 0
    resolved_cases: int = 0
    false_positive_rate: float = 0.0
    avg_classification_confidence: float = 0.0
    alerts_by_category: dict[str, int] = {}
    alerts_by_severity: dict[str, int] = {}
    alerts_over_time: list[dict] = []
    top_source_ips: list[dict] = []
    top_mitre_techniques: list[dict] = []
