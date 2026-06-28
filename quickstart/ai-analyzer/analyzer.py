#!/usr/bin/env python3
"""
AI Analyzer for smap-grafana-dashboard

- Reads scan data from the existing SQLite database (smap.db)
- Sends enriched host / scan / diff context to Ollama for analysis
- Stores AI-generated insights in NEW additive tables only
- Does NOT modify historical/base schema creation
"""

import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

DB_PATH       = os.getenv("DB_PATH", "/app/data/smap.db")
OLLAMA_HOST   = os.getenv("OLLAMA_HOST", "http://ollama:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "phi3:mini")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "500"))
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))
OLLAMA_RETRIES = int(os.getenv("OLLAMA_RETRIES", "3"))
OLLAMA_RETRY_DELAY = float(os.getenv("OLLAMA_RETRY_DELAY", "2.0"))
MAX_SCAN_CONTEXT_CHARS = int(os.getenv("MAX_SCAN_CONTEXT_CHARS", "16000"))
MAX_HOST_PORTS = int(os.getenv("MAX_HOST_PORTS", "40"))
MAX_HOST_VULNS = int(os.getenv("MAX_HOST_VULNS", "20"))
MAX_SCAN_TOP_HOSTS = int(os.getenv("MAX_SCAN_TOP_HOSTS", "15"))
MAX_SCAN_TOP_CVES = int(os.getenv("MAX_SCAN_TOP_CVES", "15"))
MAX_SCAN_TOP_SERVICES = int(os.getenv("MAX_SCAN_TOP_SERVICES", "15"))
PROMPT_VERSION = os.getenv("PROMPT_VERSION", "v2")

SENSITIVE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5000: "registry",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "kubernetes-api",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    9000: "admin-alt",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    27017: "mongodb",
}

ADMIN_KEYWORDS = {
    "ssh", "rdp", "vnc", "winrm", "docker", "kubernetes", "kubernetes-api",
    "cockpit", "webmin", "jenkins", "grafana", "kibana", "elasticsearch",
    "prometheus", "mongodb", "redis", "mysql", "postgresql", "mssql",
    "oracle", "memcached"
}

WEB_KEYWORDS = {
    "http", "https", "nginx", "apache", "iis", "tomcat", "caddy",
    "traefik", "gunicorn", "uvicorn"
}

DB_KEYWORDS = {
    "mysql", "mariadb", "postgres", "postgresql", "redis", "mongodb",
    "oracle", "mssql", "memcached", "elasticsearch"
}


# --------------------------------------------------------------------
# AI-only additive schema
# --------------------------------------------------------------------
AI_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_scan_analysis (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL REFERENCES scans(id),
    analyzed_at         TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    prompt_version      TEXT,
    status              TEXT,
    confidence          REAL,
    risk_level          TEXT,
    summary             TEXT,
    executive_summary   TEXT,
    technical_summary   TEXT,
    recommendations     TEXT,   -- JSON array
    top_risks           TEXT,   -- JSON array
    top_priorities      TEXT,   -- JSON array
    data_gaps           TEXT,   -- JSON array
    raw                 TEXT,
    input_hash          TEXT,
    context_size        INTEGER,
    duration_ms         INTEGER,
    UNIQUE(scan_id, model)
);

CREATE TABLE IF NOT EXISTS ai_host_analysis (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL REFERENCES scans(id),
    host_id             INTEGER NOT NULL REFERENCES hosts(id),
    analyzed_at         TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    prompt_version      TEXT,
    status              TEXT,
    confidence          REAL,
    risk_level          TEXT,
    risk_score          REAL,
    priority            TEXT,
    suspected_role      TEXT,
    summary             TEXT,
    key_findings        TEXT,   -- JSON array
    likely_entry_points TEXT,   -- JSON array
    risks               TEXT,   -- JSON array
    actions             TEXT,   -- JSON array
    data_gaps           TEXT,   -- JSON array
    raw                 TEXT,
    input_hash          TEXT,
    context_size        INTEGER,
    duration_ms         INTEGER,
    UNIQUE(host_id, model)
);

CREATE TABLE IF NOT EXISTS ai_diff_analysis (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    latest_scan_id      INTEGER NOT NULL REFERENCES scans(id),
    previous_scan_id    INTEGER NOT NULL REFERENCES scans(id),
    analyzed_at         TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    prompt_version      TEXT,
    status              TEXT,
    confidence          REAL,
    risk_trend          TEXT,
    summary             TEXT,
    notable_changes     TEXT,   -- JSON array
    priority_actions    TEXT,   -- JSON array
    top_regressions     TEXT,   -- JSON array
    top_improvements    TEXT,   -- JSON array
    raw                 TEXT,
    input_hash          TEXT,
    context_size        INTEGER,
    duration_ms         INTEGER,
    UNIQUE(latest_scan_id, previous_scan_id, model)
);

CREATE INDEX IF NOT EXISTS idx_ai_scan_scan  ON ai_scan_analysis(scan_id);
CREATE INDEX IF NOT EXISTS idx_ai_host_host  ON ai_host_analysis(host_id);
CREATE INDEX IF NOT EXISTS idx_ai_host_scan  ON ai_host_analysis(scan_id);
CREATE INDEX IF NOT EXISTS idx_ai_host_risk  ON ai_host_analysis(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_diff_pair  ON ai_diff_analysis(latest_scan_id, previous_scan_id);
"""


# --------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------
HOST_PROMPT = """You are a senior cybersecurity analyst specialized in external attack surface review, vulnerability triage, and remediation prioritization.

Analyze the following host data and return STRICT JSON only.

Rules:
- Do not invent facts not present in the input.
- Correlate exposure, services, versions, and vulnerabilities.
- Prioritize internet-exposed, admin, and database services.
- Risk score must be between 0.0 and 10.0.
- priority must be one of P1, P2, P3, P4.
- Keep the summary concise but specific.
- actions must be concrete and actionable.
- confidence must be between 0.0 and 1.0.

Return exactly:
{{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_score": 0.0,
  "confidence": 0.0,
  "priority": "P1|P2|P3|P4",
  "suspected_role": "string",
  "summary": "2-4 sentence assessment",
  "key_findings": ["string"],
  "likely_entry_points": [
    {{"surface": "string", "reason": "string"}}
  ],
  "risks": [
    {{"port": 0, "service": "string", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "reason": "string"}}
  ],
  "actions": [
    {{"priority": "P1|P2|P3", "action": "string", "reason": "string"}}
  ],
  "data_gaps": ["string"]
}}

Host data:
{data}

Respond with JSON only.
"""

SCAN_PROMPT = """You are a senior cybersecurity analyst preparing an executive and technical assessment of a reconnaissance/vulnerability scan.

Analyze the following scan context and return STRICT JSON only.

Rules:
- Do not invent facts not present in the input.
- Separate executive and technical perspective.
- Prioritize the most urgent exposures first.
- confidence must be between 0.0 and 1.0.

Return exactly:
{{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0,
  "summary": "3-5 sentence overall summary",
  "executive_summary": "2-4 sentence business-oriented summary",
  "technical_summary": "2-5 sentence technical summary",
  "recommendations": ["string"],
  "top_risks": ["string"],
  "top_priorities": [
    {{"type": "host|service|cve", "target": "string", "priority": "P1|P2|P3|P4", "reason": "string"}}
  ],
  "data_gaps": ["string"]
}}

Scan data:
{data}

Respond with JSON only.
"""

DIFF_PROMPT = """You are a senior cybersecurity analyst comparing two consecutive scans.

Analyze the delta and return STRICT JSON only.

Rules:
- Focus on what changed and why it matters.
- Highlight regressions and improvements.
- Do not invent facts not present in the input.
- confidence must be between 0.0 and 1.0.

Return exactly:
{{
  "risk_trend": "IMPROVING|STABLE|WORSENING",
  "confidence": 0.0,
  "summary": "2-5 sentence delta summary",
  "notable_changes": ["string"],
  "priority_actions": ["string"],
  "top_regressions": ["string"],
  "top_improvements": ["string"]
}}

Diff data:
{data}

Respond with JSON only.
"""


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def clamp(v: float, low: float, high: float) -> float:
    return max(low, min(high, v))


def normalize_risk_level(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return s
    return "UNKNOWN"


def normalize_priority(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s in {"P1", "P2", "P3", "P4"}:
        return s
    return "P3"


def normalize_risk_trend(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s in {"IMPROVING", "STABLE", "WORSENING"}:
        return s
    return "STABLE"


def normalize_float(v: Any, default: float = 0.0, low: float = 0.0, high: float = 10.0) -> float:
    try:
        f = float(v)
    except Exception:
        return default
    return clamp(f, low, high)


def ensure_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except Exception:
            return [line.strip("-• \t") for line in s.splitlines() if line.strip()]
    return [v]


def extract_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}

    # direct
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # markdown fenced block
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence_match:
        candidate = fence_match.group(1)
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

    # first balanced JSON object
    start = text.find("{")
    if start == -1:
        return {}

    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        return obj
                except Exception:
                    break
    return {}


def call_ollama(prompt: str, use_json_format: bool = True) -> Tuple[str, int]:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
        }
    }
    if use_json_format:
        payload["format"] = "json"

    t0 = time.time()
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    duration_ms = int((time.time() - t0) * 1000)
    return r.json().get("response", ""), duration_ms


def call_ollama_resilient(prompt: str) -> Tuple[str, int]:
    """
    Resilient call strategy:
    1) Try strict JSON mode first.
    2) On failure, retry without explicit format to bypass some Ollama 500 cases.
    3) Retry a few times with backoff.
    """
    last_error: Optional[Exception] = None
    modes = [True, False]

    for attempt in range(1, OLLAMA_RETRIES + 1):
        for use_json in modes:
            try:
                return call_ollama(prompt, use_json_format=use_json)
            except Exception as e:
                last_error = e
                mode_label = "json-format" if use_json else "plain-format"
                print(f"  [WARN] Ollama attempt {attempt}/{OLLAMA_RETRIES} failed ({mode_label}): {e}")

        if attempt < OLLAMA_RETRIES:
            time.sleep(OLLAMA_RETRY_DELAY * attempt)

    raise RuntimeError(f"Ollama failed after {OLLAMA_RETRIES} attempts: {last_error}")


def build_scan_fallback(scan_ctx: Dict[str, Any], reason: str) -> Dict[str, Any]:
    scan = scan_ctx.get("scan", {})
    metrics = scan_ctx.get("metrics", {})
    sev = scan_ctx.get("severity_breakdown", {}) or {}
    top_hosts = scan_ctx.get("top_risky_hosts", []) or []
    top_cves = scan_ctx.get("top_cves", []) or []

    total_hosts = int(scan.get("total_hosts") or 0)
    total_vulns = int(scan.get("total_vulns") or 0)
    critical_hosts = int(metrics.get("hosts_with_critical_exposure") or 0)
    vuln_hosts_pct = float(metrics.get("hosts_with_vulns_pct") or 0)

    risk_level = "LOW"
    if critical_hosts > 0 or float(sev.get("CRITICAL", 0)) > 0:
        risk_level = "CRITICAL"
    elif float(sev.get("HIGH", 0)) > 0 or vuln_hosts_pct >= 40:
        risk_level = "HIGH"
    elif float(sev.get("MEDIUM", 0)) > 0 or vuln_hosts_pct >= 20:
        risk_level = "MEDIUM"

    top_host_text = ", ".join([str(h.get("ip")) for h in top_hosts[:3] if h.get("ip")]) or "n/a"
    top_cve_text = ", ".join([str(v.get("cve")) for v in top_cves[:3] if v.get("cve")]) or "n/a"

    summary = (
        f"Fallback AI brief for scan #{scan.get('id')}: {total_hosts} hosts, {total_vulns} vulnerabilities, "
        f"{critical_hosts} hosts with critical exposure. Top risky hosts: {top_host_text}."
    )
    executive_summary = (
        f"Current exposure indicates a {risk_level} posture based on observed vulnerability density and critical host count. "
        f"Priority should focus on high-impact assets and severe CVEs while model generation is temporarily degraded."
    )
    technical_summary = (
        f"Severity breakdown: CRITICAL={int(sev.get('CRITICAL', 0))}, HIGH={int(sev.get('HIGH', 0))}, "
        f"MEDIUM={int(sev.get('MEDIUM', 0))}, LOW={int(sev.get('LOW', 0))}, UNKNOWN={int(sev.get('UNKNOWN', 0))}. "
        f"Top CVEs: {top_cve_text}."
    )

    recs = [
        "Prioritize remediation for CRITICAL and HIGH findings on internet-exposed hosts.",
        "Validate patch status on top risky hosts and re-run targeted scans.",
        "Review attack-surface services and reduce unnecessary exposed ports.",
    ]
    gaps = [f"LLM generation degraded: {str(reason)[:220]}"]

    return {
        "risk_level": risk_level,
        "confidence": 0.55,
        "summary": summary,
        "executive_summary": executive_summary,
        "technical_summary": technical_summary,
        "recommendations": recs,
        "top_risks": [
            f"Critical exposure hosts: {critical_hosts}",
            f"Vulnerable host ratio: {vuln_hosts_pct:.1f}%",
            f"Top CVE sample: {top_cve_text}",
        ],
        "top_priorities": [
            {"type": "host", "target": top_host_text, "priority": "P1", "reason": "Highest observed exposure concentration"},
            {"type": "cve", "target": top_cve_text, "priority": "P1", "reason": "Most severe CVE cluster in scan"},
        ],
        "data_gaps": gaps,
    }


def compact_scan_context(scan_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only high-signal fields to avoid oversized prompts on large scans."""
    return {
        "scan": scan_ctx.get("scan", {}),
        "metrics": scan_ctx.get("metrics", {}),
        "severity_breakdown": scan_ctx.get("severity_breakdown", {}),
        "top_risky_hosts": (scan_ctx.get("top_risky_hosts", []) or [])[:8],
        "top_cves": (scan_ctx.get("top_cves", []) or [])[:10],
        "top_services": (scan_ctx.get("top_services", []) or [])[:10],
        "top_orgs": (scan_ctx.get("top_orgs", []) or [])[:8],
        "delta_summary": scan_ctx.get("delta_summary", {}),
    }


def wait_for_ollama():
    for _ in range(120):
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            if r.status_code == 200:
                tags = r.json().get("models", [])
                names = [t.get("name", "") for t in tags]
                print(f"[OK] Ollama ready. Available models: {names}")
                if any(OLLAMA_MODEL in n for n in names):
                    return True
                print(f"[WAIT] Model {OLLAMA_MODEL} not yet pulled...")
        except Exception as e:
            print(f"[WAIT] Ollama not reachable yet ({e})")
        time.sleep(5)
    return False


def wait_for_db():
    for _ in range(60):
        if os.path.exists(DB_PATH):
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("SELECT 1 FROM scans LIMIT 1;")
                conn.close()
                print(f"[OK] Database ready at {DB_PATH}")
                return True
            except sqlite3.Error as e:
                print(f"[WAIT] DB not ready: {e}")
        else:
            print(f"[WAIT] DB file not found yet at {DB_PATH}")
        time.sleep(5)
    return False


# --------------------------------------------------------------------
# DB / schema
# --------------------------------------------------------------------
def init_ai_schema(conn: sqlite3.Connection):
    conn.executescript(AI_SCHEMA)
    conn.commit()


def has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name=?
    """, (table_name,)).fetchone()
    return bool(row)


def get_columns(conn: sqlite3.Connection, table_name: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return [r[1] for r in rows]
    except Exception:
        return []


def get_pending_scans(conn: sqlite3.Connection):
    cur = conn.execute("""
        SELECT s.id, s.scan_time, s.total_hosts, s.total_ports, s.total_vulns
        FROM scans s
        LEFT JOIN ai_scan_analysis a
          ON a.scan_id = s.id AND a.model = ?
        WHERE a.id IS NULL
        ORDER BY s.id DESC
    """, (OLLAMA_MODEL,))
    return cur.fetchall()


def get_pending_hosts(conn: sqlite3.Connection, scan_id: int):
    cur = conn.execute("""
        SELECT h.id, h.ip
        FROM hosts h
        LEFT JOIN ai_host_analysis a
          ON a.host_id = h.id AND a.model = ?
        WHERE h.scan_id = ? AND a.id IS NULL
        ORDER BY h.id ASC
    """, (OLLAMA_MODEL, scan_id))
    return cur.fetchall()


def get_previous_scan_id(conn: sqlite3.Connection, scan_id: int) -> Optional[int]:
    row = conn.execute("""
        SELECT id
        FROM scans
        WHERE id < ?
        ORDER BY id DESC
        LIMIT 1
    """, (scan_id,)).fetchone()
    return row[0] if row else None


def diff_already_done(conn: sqlite3.Connection, latest_scan_id: int, previous_scan_id: int) -> bool:
    row = conn.execute("""
        SELECT id
        FROM ai_diff_analysis
        WHERE latest_scan_id = ? AND previous_scan_id = ? AND model = ?
        LIMIT 1
    """, (latest_scan_id, previous_scan_id, OLLAMA_MODEL)).fetchone()
    return bool(row)


# --------------------------------------------------------------------
# Context builders
# --------------------------------------------------------------------
def classify_service_name(service: str, product: str) -> List[str]:
    s = f"{service or ''} {product or ''}".lower()
    tags = []
    if any(k in s for k in ADMIN_KEYWORDS):
        tags.append("admin")
    if any(k in s for k in WEB_KEYWORDS):
        tags.append("web")
    if any(k in s for k in DB_KEYWORDS):
        tags.append("database")
    return tags


def severity_counter(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    c = Counter()
    for v in vulns:
        sev = normalize_risk_level(v.get("severity"))
        if sev == "UNKNOWN":
            sev = "UNKNOWN"
        c[sev] += 1
    return dict(c)


def summarize_ports(ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    sensitive = []
    admin = []
    web = []
    dbs = []
    services = Counter()

    for p in ports:
        port = int(p.get("port") or 0)
        service = str(p.get("service") or "").lower()
        product = str(p.get("product") or "").lower()

        if port in SENSITIVE_PORTS:
            sensitive.append({"port": port, "label": SENSITIVE_PORTS[port]})

        tags = classify_service_name(service, product)
        if "admin" in tags:
            admin.append(port)
        if "web" in tags:
            web.append(port)
        if "database" in tags:
            dbs.append(port)

        key = service or product or str(port)
        services[key] += 1

    top_services = [{"name": k, "count": v} for k, v in services.most_common(10)]
    return {
        "open_port_count": len(ports),
        "sensitive_ports": sensitive,
        "admin_ports": sorted(set(admin)),
        "web_ports": sorted(set(web)),
        "database_ports": sorted(set(dbs)),
        "top_services": top_services,
    }


def compute_static_host_score(ctx: Dict[str, Any]) -> float:
    host = ctx.get("host", {})
    exposure = ctx.get("exposure", {})
    vuln_summary = ctx.get("vuln_summary", {})

    score = 0.0
    max_cvss = float(vuln_summary.get("max_cvss") or host.get("max_cvss") or 0)
    critical = int(vuln_summary.get("critical", 0))
    high = int(vuln_summary.get("high", 0))
    open_ports = int(exposure.get("open_port_count", 0))
    admin_ports = exposure.get("admin_ports", [])
    db_ports = exposure.get("database_ports", [])
    sensitive_ports = exposure.get("sensitive_ports", [])

    if max_cvss >= 9.0:
        score += 3.0
    elif max_cvss >= 7.0:
        score += 2.0
    elif max_cvss >= 4.0:
        score += 1.0

    score += min(critical * 1.2, 3.0)
    score += min(high * 0.4, 2.0)
    score += min(open_ports * 0.1, 1.0)

    if admin_ports:
        score += 1.0
    if db_ports:
        score += 1.0
    if len(sensitive_ports) >= 3:
        score += 1.0

    return round(clamp(score, 0.0, 10.0), 2)


def compact_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def prioritize_host_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ports = ctx.get("ports", [])
    vulns = ctx.get("vulnerabilities", [])

    def port_rank(p):
        port = int(p.get("port") or 0)
        service = str(p.get("service") or "").lower()
        product = str(p.get("product") or "").lower()
        score = 0
        if port in SENSITIVE_PORTS:
            score += 5
        if "admin" in classify_service_name(service, product):
            score += 4
        if "database" in classify_service_name(service, product):
            score += 3
        if "web" in classify_service_name(service, product):
            score += 2
        return score

    def vuln_rank(v):
        cvss = float(v.get("cvss") or 0)
        sev = normalize_risk_level(v.get("severity"))
        bonus = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
        return cvss + bonus

    ports_sorted = sorted(ports, key=port_rank, reverse=True)[:MAX_HOST_PORTS]
    vulns_sorted = sorted(vulns, key=vuln_rank, reverse=True)[:MAX_HOST_VULNS]

    out = dict(ctx)
    out["ports"] = ports_sorted
    out["vulnerabilities"] = vulns_sorted
    return out


def get_host_context(conn: sqlite3.Connection, host_id: int) -> Optional[Dict[str, Any]]:
    host = conn.execute("""
        SELECT id, scan_id, ip, hostname, os, country, org, asn, isp,
               vuln_count, max_cvss, risk_level
        FROM hosts WHERE id = ?
    """, (host_id,)).fetchone()
    if not host:
        return None

    ports_rows = conn.execute("""
        SELECT port, protocol, service, product, version, state
        FROM ports
        WHERE host_id = ?
        ORDER BY port ASC
    """, (host_id,)).fetchall()

    vuln_rows = conn.execute("""
        SELECT cve, cvss, severity, summary
        FROM vulnerabilities
        WHERE host_id = ?
        ORDER BY cvss DESC, cve ASC
    """, (host_id,)).fetchall()

    previous_host = conn.execute("""
        SELECT h2.id
        FROM hosts h1
        JOIN hosts h2
          ON h2.ip = h1.ip
         AND h2.id != h1.id
         AND h2.scan_id < h1.scan_id
        WHERE h1.id = ?
        ORDER BY h2.scan_id DESC
        LIMIT 1
    """, (host_id,)).fetchone()

    ports = [
        {
            "port": p[0],
            "proto": p[1],
            "service": p[2],
            "product": p[3],
            "version": p[4],
            "state": p[5],
            "tags": classify_service_name(p[2], p[3]),
        }
        for p in ports_rows
    ]

    vulnerabilities = [
        {"cve": v[0], "cvss": v[1], "severity": v[2], "summary": v[3]}
        for v in vuln_rows
    ]

    sev_counts = severity_counter(vulnerabilities)
    cvss_values = [float(v.get("cvss") or 0) for v in vulnerabilities if v.get("cvss") is not None]
    avg_cvss = round(sum(cvss_values) / len(cvss_values), 2) if cvss_values else 0.0

    versions = []
    for p in ports:
        if p.get("product") or p.get("version"):
            versions.append({
                "service": p.get("service"),
                "product": p.get("product"),
                "version": p.get("version"),
                "port": p.get("port"),
            })

    exposure = summarize_ports(ports)

    trend = {
        "is_new_host": previous_host is None,
        "new_ports_since_last_scan": [],
        "closed_ports_since_last_scan": [],
        "new_cves_since_last_scan": [],
        "resolved_cves_since_last_scan": [],
        "risk_delta": "UNKNOWN",
    }

    if previous_host:
        prev_host_id = previous_host[0]

        prev_ports = {
            r[0]
            for r in conn.execute("SELECT port FROM ports WHERE host_id = ?", (prev_host_id,)).fetchall()
        }
        cur_ports = {int(p["port"]) for p in ports}
        trend["new_ports_since_last_scan"] = sorted(cur_ports - prev_ports)
        trend["closed_ports_since_last_scan"] = sorted(prev_ports - cur_ports)

        prev_cves = {
            r[0]
            for r in conn.execute("SELECT cve FROM vulnerabilities WHERE host_id = ?", (prev_host_id,)).fetchall()
        }
        cur_cves = {str(v["cve"]) for v in vulnerabilities}
        trend["new_cves_since_last_scan"] = sorted(cur_cves - prev_cves)[:20]
        trend["resolved_cves_since_last_scan"] = sorted(prev_cves - cur_cves)[:20]

        prev_max = conn.execute("SELECT max_cvss FROM hosts WHERE id = ?", (prev_host_id,)).fetchone()
        prev_max_cvss = float(prev_max[0] or 0) if prev_max else 0.0
        cur_max_cvss = float(host[10] or 0)

        if cur_max_cvss > prev_max_cvss:
            trend["risk_delta"] = "UP"
        elif cur_max_cvss < prev_max_cvss:
            trend["risk_delta"] = "DOWN"
        else:
            trend["risk_delta"] = "STABLE"

    ctx = {
        "host": {
            "id": host[0],
            "scan_id": host[1],
            "ip": host[2],
            "hostname": host[3],
            "os": host[4],
            "country": host[5],
            "org": host[6],
            "asn": host[7],
            "isp": host[8],
            "vuln_count": host[9],
            "max_cvss": host[10],
            "risk_level_static": host[11],
        },
        "vuln_summary": {
            "total": len(vulnerabilities),
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            "unknown": sev_counts.get("UNKNOWN", 0),
            "max_cvss": float(host[10] or 0),
            "avg_cvss": avg_cvss,
        },
        "exposure": exposure,
        "detected_versions": versions[:20],
        "trend": trend,
        "ports": ports,
        "vulnerabilities": vulnerabilities,
    }

    ctx["static_risk_score"] = compute_static_host_score(ctx)
    return prioritize_host_context(ctx)


def get_scan_context(conn: sqlite3.Connection, scan_id: int) -> Dict[str, Any]:
    scan = conn.execute("""
        SELECT id, scan_time, total_hosts, total_ports, total_vulns, scanner_version, raw_file
        FROM scans WHERE id = ?
    """, (scan_id,)).fetchone()

    if not scan:
        return {}

    severity_rows = conn.execute("""
        SELECT COALESCE(severity, 'UNKNOWN'), COUNT(*)
        FROM vulnerabilities
        WHERE scan_id = ?
        GROUP BY COALESCE(severity, 'UNKNOWN')
    """, (scan_id,)).fetchall()

    top_hosts = conn.execute("""
        SELECT ip, hostname, risk_level, max_cvss, vuln_count
        FROM hosts
        WHERE scan_id = ?
        ORDER BY max_cvss DESC, vuln_count DESC
        LIMIT ?
    """, (scan_id, MAX_SCAN_TOP_HOSTS)).fetchall()

    top_cves = conn.execute("""
        SELECT cve, MAX(cvss) AS max_cvss, COALESCE(severity, 'UNKNOWN') AS severity, COUNT(*) AS affected_hosts
        FROM vulnerabilities
        WHERE scan_id = ?
        GROUP BY cve, COALESCE(severity, 'UNKNOWN')
        ORDER BY max_cvss DESC, affected_hosts DESC
        LIMIT ?
    """, (scan_id, MAX_SCAN_TOP_CVES)).fetchall()

    service_rows = conn.execute("""
        SELECT COALESCE(NULLIF(p.service,''), NULLIF(p.product,''), 'unknown') AS svc, COUNT(*)
        FROM ports p
        JOIN hosts h ON h.id = p.host_id
        WHERE h.scan_id = ?
        GROUP BY svc
        ORDER BY COUNT(*) DESC
        LIMIT ?
    """, (scan_id, MAX_SCAN_TOP_SERVICES)).fetchall()

    sensitive_open = conn.execute("""
        SELECT COUNT(*)
        FROM ports p
        JOIN hosts h ON h.id = p.host_id
        WHERE h.scan_id = ?
          AND p.port IN (21,22,23,25,111,135,139,445,1433,1521,2049,2375,3306,3389,5432,5601,5900,5985,5986,6379,6443,8080,8443,9090,9200,11211,27017)
    """, (scan_id,)).fetchone()[0]

    hosts_with_vulns = conn.execute("""
        SELECT COUNT(*)
        FROM hosts
        WHERE scan_id = ? AND COALESCE(vuln_count, 0) > 0
    """, (scan_id,)).fetchone()[0]

    critical_hosts = conn.execute("""
        SELECT COUNT(*)
        FROM hosts
        WHERE scan_id = ? AND COALESCE(max_cvss, 0) >= 9
    """, (scan_id,)).fetchone()[0]

    top_orgs = conn.execute("""
        SELECT COALESCE(org, 'UNKNOWN') AS org, COUNT(*)
        FROM hosts
        WHERE scan_id = ?
        GROUP BY COALESCE(org, 'UNKNOWN')
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """, (scan_id,)).fetchall()

    previous_scan_id = get_previous_scan_id(conn, scan_id)
    delta_summary = {}
    if previous_scan_id:
        delta_summary = compute_scan_delta(conn, previous_scan_id, scan_id)

    total_hosts = int(scan[2] or 0)
    vuln_ratio = round((hosts_with_vulns / total_hosts) * 100, 2) if total_hosts else 0.0

    return {
        "scan": {
            "id": scan[0],
            "scan_time": scan[1],
            "total_hosts": scan[2],
            "total_ports": scan[3],
            "total_vulns": scan[4],
            "scanner_version": scan[5],
            "raw_file": scan[6],
        },
        "metrics": {
            "hosts_with_vulns": hosts_with_vulns,
            "hosts_with_vulns_pct": vuln_ratio,
            "hosts_with_critical_exposure": critical_hosts,
            "sensitive_open_ports_count": sensitive_open,
        },
        "severity_breakdown": {s[0]: s[1] for s in severity_rows},
        "top_risky_hosts": [
            {
                "ip": h[0],
                "hostname": h[1],
                "risk_level": h[2],
                "max_cvss": h[3],
                "vuln_count": h[4],
            }
            for h in top_hosts
        ],
        "top_cves": [
            {
                "cve": r[0],
                "max_cvss": r[1],
                "severity": r[2],
                "affected_hosts": r[3],
            }
            for r in top_cves
        ],
        "top_services": [{"service": r[0], "count": r[1]} for r in service_rows],
        "top_orgs": [{"org": r[0], "count": r[1]} for r in top_orgs],
        "delta_summary": delta_summary,
    }


def compute_scan_delta(conn: sqlite3.Connection, previous_scan_id: int, latest_scan_id: int) -> Dict[str, Any]:
    prev_hosts = {
        r[0]: {"hostname": r[1], "risk_level": r[2], "max_cvss": r[3]}
        for r in conn.execute("""
            SELECT ip, hostname, risk_level, max_cvss
            FROM hosts WHERE scan_id = ?
        """, (previous_scan_id,)).fetchall()
    }

    latest_hosts = {
        r[0]: {"hostname": r[1], "risk_level": r[2], "max_cvss": r[3]}
        for r in conn.execute("""
            SELECT ip, hostname, risk_level, max_cvss
            FROM hosts WHERE scan_id = ?
        """, (latest_scan_id,)).fetchall()
    }

    prev_cves = {
        (r[0], r[1])
        for r in conn.execute("""
            SELECT v.cve, h.ip
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE v.scan_id = ?
        """, (previous_scan_id,)).fetchall()
    }

    latest_cves = {
        (r[0], r[1])
        for r in conn.execute("""
            SELECT v.cve, h.ip
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE v.scan_id = ?
        """, (latest_scan_id,)).fetchall()
    }

    new_hosts = sorted(set(latest_hosts) - set(prev_hosts))
    gone_hosts = sorted(set(prev_hosts) - set(latest_hosts))
    new_cves = sorted(latest_cves - prev_cves)
    resolved_cves = sorted(prev_cves - latest_cves)

    trend = "STABLE"
    if len(new_cves) > len(resolved_cves) or len(new_hosts) > len(gone_hosts):
        trend = "WORSENING"
    elif len(resolved_cves) > len(new_cves):
        trend = "IMPROVING"

    return {
        "previous_scan_id": previous_scan_id,
        "latest_scan_id": latest_scan_id,
        "new_hosts_count": len(new_hosts),
        "gone_hosts_count": len(gone_hosts),
        "new_cves_count": len(new_cves),
        "resolved_cves_count": len(resolved_cves),
        "overall_trend": trend,
        "sample_new_hosts": new_hosts[:10],
        "sample_gone_hosts": gone_hosts[:10],
        "sample_new_cves": [{"cve": c, "ip": ip} for c, ip in new_cves[:10]],
        "sample_resolved_cves": [{"cve": c, "ip": ip} for c, ip in resolved_cves[:10]],
    }


def get_diff_context(conn: sqlite3.Connection, previous_scan_id: int, latest_scan_id: int) -> Dict[str, Any]:
    previous = conn.execute("""
        SELECT id, scan_time, total_hosts, total_ports, total_vulns
        FROM scans WHERE id = ?
    """, (previous_scan_id,)).fetchone()

    latest = conn.execute("""
        SELECT id, scan_time, total_hosts, total_ports, total_vulns
        FROM scans WHERE id = ?
    """, (latest_scan_id,)).fetchone()

    if not previous or not latest:
        return {}

    new_hosts_rows = conn.execute("""
        SELECT h.ip, h.hostname, h.risk_level, h.max_cvss
        FROM hosts h
        WHERE h.scan_id = ?
          AND h.ip NOT IN (SELECT ip FROM hosts WHERE scan_id = ?)
        ORDER BY COALESCE(h.max_cvss, 0) DESC, h.ip ASC
        LIMIT 20
    """, (latest_scan_id, previous_scan_id)).fetchall()

    gone_hosts_rows = conn.execute("""
        SELECT h.ip, h.hostname, h.risk_level, h.max_cvss
        FROM hosts h
        WHERE h.scan_id = ?
          AND h.ip NOT IN (SELECT ip FROM hosts WHERE scan_id = ?)
        ORDER BY COALESCE(h.max_cvss, 0) DESC, h.ip ASC
        LIMIT 20
    """, (previous_scan_id, latest_scan_id)).fetchall()

    new_cves_rows = conn.execute("""
        SELECT v.cve, h.ip, v.cvss, v.severity
        FROM vulnerabilities v
        JOIN hosts h ON h.id = v.host_id
        WHERE v.scan_id = ?
          AND NOT EXISTS (
            SELECT 1
            FROM vulnerabilities p
            JOIN hosts hp ON hp.id = p.host_id
            WHERE p.scan_id = ?
              AND p.cve = v.cve
              AND hp.ip = h.ip
          )
        ORDER BY COALESCE(v.cvss, 0) DESC, v.cve ASC
        LIMIT 25
    """, (latest_scan_id, previous_scan_id)).fetchall()

    resolved_cves_rows = conn.execute("""
        SELECT v.cve, h.ip, v.cvss, v.severity
        FROM vulnerabilities v
        JOIN hosts h ON h.id = v.host_id
        WHERE v.scan_id = ?
          AND NOT EXISTS (
            SELECT 1
            FROM vulnerabilities p
            JOIN hosts hp ON hp.id = p.host_id
            WHERE p.scan_id = ?
              AND p.cve = v.cve
              AND hp.ip = h.ip
          )
        ORDER BY COALESCE(v.cvss, 0) DESC, v.cve ASC
        LIMIT 25
    """, (previous_scan_id, latest_scan_id)).fetchall()

    delta = compute_scan_delta(conn, previous_scan_id, latest_scan_id)

    return {
        "previous_scan": {
            "id": previous[0],
            "scan_time": previous[1],
            "total_hosts": previous[2],
            "total_ports": previous[3],
            "total_vulns": previous[4],
        },
        "latest_scan": {
            "id": latest[0],
            "scan_time": latest[1],
            "total_hosts": latest[2],
            "total_ports": latest[3],
            "total_vulns": latest[4],
        },
        "delta_summary": delta,
        "new_hosts": [
            {"ip": r[0], "hostname": r[1], "risk_level": r[2], "max_cvss": r[3]}
            for r in new_hosts_rows
        ],
        "gone_hosts": [
            {"ip": r[0], "hostname": r[1], "risk_level": r[2], "max_cvss": r[3]}
            for r in gone_hosts_rows
        ],
        "new_cves": [
            {"cve": r[0], "ip": r[1], "cvss": r[2], "severity": r[3]}
            for r in new_cves_rows
        ],
        "resolved_cves": [
            {"cve": r[0], "ip": r[1], "cvss": r[2], "severity": r[3]}
            for r in resolved_cves_rows
        ],
    }


# --------------------------------------------------------------------
# Normalizers
# --------------------------------------------------------------------
def normalize_host_result(result: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    out["risk_level"] = normalize_risk_level(result.get("risk_level"))
    out["risk_score"] = normalize_float(result.get("risk_score"), default=ctx.get("static_risk_score", 0.0), low=0.0, high=10.0)
    out["confidence"] = normalize_float(result.get("confidence"), default=0.7, low=0.0, high=1.0)
    out["priority"] = normalize_priority(result.get("priority"))
    out["suspected_role"] = str(result.get("suspected_role") or "").strip()[:200]
    out["summary"] = str(result.get("summary") or "").strip()

    key_findings = [str(x).strip() for x in ensure_list(result.get("key_findings")) if str(x).strip()]
    out["key_findings"] = key_findings[:10]

    ep_list = []
    for item in ensure_list(result.get("likely_entry_points"))[:10]:
        if isinstance(item, dict):
            ep_list.append({
                "surface": str(item.get("surface") or "").strip(),
                "reason": str(item.get("reason") or "").strip(),
            })
        else:
            ep_list.append({"surface": str(item), "reason": ""})
    out["likely_entry_points"] = ep_list

    risks = []
    for item in ensure_list(result.get("risks"))[:15]:
        if isinstance(item, dict):
            risks.append({
                "port": int(item.get("port") or 0),
                "service": str(item.get("service") or "").strip(),
                "severity": normalize_risk_level(item.get("severity")),
                "reason": str(item.get("reason") or "").strip(),
            })
    out["risks"] = risks

    actions = []
    for item in ensure_list(result.get("actions"))[:15]:
        if isinstance(item, dict):
            actions.append({
                "priority": normalize_priority(item.get("priority")),
                "action": str(item.get("action") or "").strip(),
                "reason": str(item.get("reason") or "").strip(),
            })
        else:
            actions.append({
                "priority": "P2",
                "action": str(item).strip(),
                "reason": "",
            })
    out["actions"] = [a for a in actions if a["action"]]

    data_gaps = [str(x).strip() for x in ensure_list(result.get("data_gaps")) if str(x).strip()]
    out["data_gaps"] = data_gaps[:10]

    if not out["summary"]:
        out["summary"] = f"Host {ctx.get('host', {}).get('ip', 'unknown')} shows {ctx.get('vuln_summary', {}).get('total', 0)} vulnerabilities and {ctx.get('exposure', {}).get('open_port_count', 0)} open ports."

    return out


def normalize_scan_result(result: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    out["risk_level"] = normalize_risk_level(result.get("risk_level"))
    out["confidence"] = normalize_float(result.get("confidence"), default=0.75, low=0.0, high=1.0)
    out["summary"] = str(result.get("summary") or "").strip()
    out["executive_summary"] = str(result.get("executive_summary") or "").strip()
    out["technical_summary"] = str(result.get("technical_summary") or "").strip()
    out["recommendations"] = [str(x).strip() for x in ensure_list(result.get("recommendations")) if str(x).strip()][:15]
    out["top_risks"] = [str(x).strip() for x in ensure_list(result.get("top_risks")) if str(x).strip()][:15]
    out["data_gaps"] = [str(x).strip() for x in ensure_list(result.get("data_gaps")) if str(x).strip()][:10]

    top_priorities = []
    for item in ensure_list(result.get("top_priorities"))[:15]:
        if isinstance(item, dict):
            top_priorities.append({
                "type": str(item.get("type") or "").strip()[:30],
                "target": str(item.get("target") or "").strip()[:200],
                "priority": normalize_priority(item.get("priority")),
                "reason": str(item.get("reason") or "").strip(),
            })
        else:
            top_priorities.append({
                "type": "item",
                "target": str(item).strip(),
                "priority": "P2",
                "reason": "",
            })
    out["top_priorities"] = top_priorities
    return out


def normalize_diff_result(result: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    out["risk_trend"] = normalize_risk_trend(result.get("risk_trend"))
    out["confidence"] = normalize_float(result.get("confidence"), default=0.75, low=0.0, high=1.0)
    out["summary"] = str(result.get("summary") or "").strip()
    out["notable_changes"] = [str(x).strip() for x in ensure_list(result.get("notable_changes")) if str(x).strip()][:15]
    out["priority_actions"] = [str(x).strip() for x in ensure_list(result.get("priority_actions")) if str(x).strip()][:15]
    out["top_regressions"] = [str(x).strip() for x in ensure_list(result.get("top_regressions")) if str(x).strip()][:15]
    out["top_improvements"] = [str(x).strip() for x in ensure_list(result.get("top_improvements")) if str(x).strip()][:15]
    return out


# --------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------
def save_host_analysis(
    conn: sqlite3.Connection,
    scan_id: int,
    host_id: int,
    result: Dict[str, Any],
    raw: str,
    prompt_input: str,
    duration_ms: int,
    status: str = "ok",
):
    conn.execute("""
        INSERT OR REPLACE INTO ai_host_analysis
        (scan_id, host_id, analyzed_at, model, prompt_version, status,
         confidence, risk_level, risk_score, priority, suspected_role, summary,
         key_findings, likely_entry_points, risks, actions, data_gaps, raw,
         input_hash, context_size, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        host_id,
        now_iso(),
        OLLAMA_MODEL,
        PROMPT_VERSION,
        status,
        result.get("confidence"),
        result.get("risk_level"),
        result.get("risk_score"),
        result.get("priority"),
        result.get("suspected_role"),
        result.get("summary"),
        json.dumps(result.get("key_findings", []), ensure_ascii=False),
        json.dumps(result.get("likely_entry_points", []), ensure_ascii=False),
        json.dumps(result.get("risks", []), ensure_ascii=False),
        json.dumps(result.get("actions", []), ensure_ascii=False),
        json.dumps(result.get("data_gaps", []), ensure_ascii=False),
        raw,
        sha256_text(prompt_input),
        len(prompt_input),
        duration_ms,
    ))
    conn.commit()


def save_scan_analysis(
    conn: sqlite3.Connection,
    scan_id: int,
    result: Dict[str, Any],
    raw: str,
    prompt_input: str,
    duration_ms: int,
    status: str = "ok",
):
    conn.execute("""
        INSERT OR REPLACE INTO ai_scan_analysis
        (scan_id, analyzed_at, model, prompt_version, status, confidence,
         risk_level, summary, executive_summary, technical_summary,
         recommendations, top_risks, top_priorities, data_gaps, raw,
         input_hash, context_size, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        now_iso(),
        OLLAMA_MODEL,
        PROMPT_VERSION,
        status,
        result.get("confidence"),
        result.get("risk_level"),
        result.get("summary"),
        result.get("executive_summary"),
        result.get("technical_summary"),
        json.dumps(result.get("recommendations", []), ensure_ascii=False),
        json.dumps(result.get("top_risks", []), ensure_ascii=False),
        json.dumps(result.get("top_priorities", []), ensure_ascii=False),
        json.dumps(result.get("data_gaps", []), ensure_ascii=False),
        raw,
        sha256_text(prompt_input),
        len(prompt_input),
        duration_ms,
    ))
    conn.commit()


def save_diff_analysis(
    conn: sqlite3.Connection,
    latest_scan_id: int,
    previous_scan_id: int,
    result: Dict[str, Any],
    raw: str,
    prompt_input: str,
    duration_ms: int,
    status: str = "ok",
):
    conn.execute("""
        INSERT OR REPLACE INTO ai_diff_analysis
        (latest_scan_id, previous_scan_id, analyzed_at, model, prompt_version, status,
         confidence, risk_trend, summary, notable_changes, priority_actions,
         top_regressions, top_improvements, raw, input_hash, context_size, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        latest_scan_id,
        previous_scan_id,
        now_iso(),
        OLLAMA_MODEL,
        PROMPT_VERSION,
        status,
        result.get("confidence"),
        result.get("risk_trend"),
        result.get("summary"),
        json.dumps(result.get("notable_changes", []), ensure_ascii=False),
        json.dumps(result.get("priority_actions", []), ensure_ascii=False),
        json.dumps(result.get("top_regressions", []), ensure_ascii=False),
        json.dumps(result.get("top_improvements", []), ensure_ascii=False),
        raw,
        sha256_text(prompt_input),
        len(prompt_input),
        duration_ms,
    ))
    conn.commit()


# --------------------------------------------------------------------
# Main processing
# --------------------------------------------------------------------
def process_host(conn: sqlite3.Connection, scan_id: int, host_id: int):
    ctx = get_host_context(conn, host_id)
    if not ctx:
        return

    data_str = compact_json(ctx)
    prompt = HOST_PROMPT.format(data=data_str)

    try:
        raw, duration_ms = call_ollama_resilient(prompt)
        parsed = extract_json_object(raw)
        result = normalize_host_result(parsed, ctx)
        save_host_analysis(conn, scan_id, host_id, result, raw, prompt, duration_ms, status="ok")
        print(
            f"     host {host_id} ({ctx['host']['ip']}) -> "
            f"{result.get('risk_level')} score={result.get('risk_score')} prio={result.get('priority')}"
        )
    except Exception as e:
        print(f"     [ERROR] host {host_id}: {e}")
        fallback = normalize_host_result({}, ctx)
        save_host_analysis(conn, scan_id, host_id, fallback, str(e), prompt, 0, status="error")


def process_scan_summary(conn: sqlite3.Connection, scan_id: int):
    prompt = ""
    scan_ctx: Dict[str, Any] = {}
    try:
        scan_ctx = get_scan_context(conn, scan_id)
        data_str = compact_json(scan_ctx)
        if len(data_str) > MAX_SCAN_CONTEXT_CHARS:
            lean_ctx = compact_scan_context(scan_ctx)
            data_str = compact_json(lean_ctx)
        prompt = SCAN_PROMPT.format(data=data_str)
        raw, duration_ms = call_ollama_resilient(prompt)
        parsed = extract_json_object(raw)
        result = normalize_scan_result(parsed)
        if not result.get("summary"):
            # If model returns malformed/empty payload, publish a deterministic fallback brief.
            result = normalize_scan_result(build_scan_fallback(scan_ctx, "empty model response"))
            save_scan_analysis(conn, scan_id, result, raw, prompt, duration_ms, status="degraded")
            print(f"  -> Scan summary saved in degraded mode (risk={result.get('risk_level')})")
            return
        save_scan_analysis(conn, scan_id, result, raw, prompt, duration_ms, status="ok")
        print(f"  -> Scan summary saved (risk={result.get('risk_level')}, confidence={result.get('confidence')})")
    except Exception as e:
        print(f"  [ERROR] scan summary: {e}")
        fallback = normalize_scan_result(build_scan_fallback(scan_ctx, str(e)))
        save_scan_analysis(conn, scan_id, fallback, str(e), prompt, 0, status="degraded")


def process_diff_summary(conn: sqlite3.Connection, latest_scan_id: int):
    previous_scan_id = get_previous_scan_id(conn, latest_scan_id)
    if not previous_scan_id:
        return

    if diff_already_done(conn, latest_scan_id, previous_scan_id):
        print(f"  -> Diff already analyzed for scans {previous_scan_id} -> {latest_scan_id}")
        return

    diff_ctx = get_diff_context(conn, previous_scan_id, latest_scan_id)
    if not diff_ctx:
        return

    data_str = compact_json(diff_ctx)
    prompt = DIFF_PROMPT.format(data=data_str)

    try:
        raw, duration_ms = call_ollama_resilient(prompt)
        parsed = extract_json_object(raw)
        result = normalize_diff_result(parsed)
        if not result.get("summary"):
            result = normalize_diff_result({
                "risk_trend": diff_ctx.get("delta_summary", {}).get("overall_trend", "STABLE"),
                "confidence": 0.6,
                "summary": "Fallback diff brief: model output was empty; using deterministic scan delta.",
                "notable_changes": [
                    f"new_hosts={diff_ctx.get('delta_summary', {}).get('new_hosts_count', 0)}",
                    f"new_cves={diff_ctx.get('delta_summary', {}).get('new_cves_count', 0)}",
                    f"resolved_cves={diff_ctx.get('delta_summary', {}).get('resolved_cves_count', 0)}",
                ],
                "priority_actions": [
                    "Review newly introduced hosts and critical CVEs from latest scan.",
                    "Validate resolved findings were effectively remediated.",
                ],
                "top_regressions": [],
                "top_improvements": [],
            })
            save_diff_analysis(conn, latest_scan_id, previous_scan_id, result, raw, prompt, duration_ms, status="degraded")
            print(f"  -> Diff summary saved in degraded mode (trend={result.get('risk_trend')})")
            return
        save_diff_analysis(conn, latest_scan_id, previous_scan_id, result, raw, prompt, duration_ms, status="ok")
        print(f"  -> Diff summary saved (trend={result.get('risk_trend')})")
    except Exception as e:
        print(f"  [ERROR] diff summary: {e}")
        fallback = normalize_diff_result({
            "risk_trend": diff_ctx.get("delta_summary", {}).get("overall_trend", "STABLE"),
            "confidence": 0.55,
            "summary": f"Fallback diff brief generated after model failure: {str(e)[:180]}",
            "notable_changes": [
                f"new_hosts={diff_ctx.get('delta_summary', {}).get('new_hosts_count', 0)}",
                f"gone_hosts={diff_ctx.get('delta_summary', {}).get('gone_hosts_count', 0)}",
                f"new_cves={diff_ctx.get('delta_summary', {}).get('new_cves_count', 0)}",
                f"resolved_cves={diff_ctx.get('delta_summary', {}).get('resolved_cves_count', 0)}",
            ],
            "priority_actions": ["Investigate regressions and prioritize newly introduced critical findings."],
            "top_regressions": [],
            "top_improvements": [],
        })
        save_diff_analysis(conn, latest_scan_id, previous_scan_id, fallback, str(e), prompt, 0, status="degraded")


def process_once():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")

    # additive only
    init_ai_schema(conn)

    scans = get_pending_scans(conn)
    if not scans:
        print("[INFO] No new scans to analyze")
        conn.close()
        return

    for scan_row in scans:
        scan_id = scan_row[0]
        print(f"[ANALYZE] Scan #{scan_id}")

        # 1) Per-host analysis
        hosts = get_pending_hosts(conn, scan_id)
        print(f"  -> {len(hosts)} host(s) to analyze")
        for h in hosts:
            host_id = h[0]
            process_host(conn, scan_id, host_id)

        # 2) Scan-level summary
        process_scan_summary(conn, scan_id)

        # 3) Diff-level summary
        process_diff_summary(conn, scan_id)

    conn.close()


def main():
    print(f"[START] AI Analyzer | model={OLLAMA_MODEL} | db={DB_PATH} | prompt_version={PROMPT_VERSION}")
    if not wait_for_db():
        print("[FATAL] Database never became ready")
        return
    if not wait_for_ollama():
        print("[FATAL] Ollama / model not ready")
        return

    while True:
        try:
            process_once()
        except Exception as e:
            print(f"[ERROR] loop: {e}")
        print(f"[SLEEP] {SCAN_INTERVAL}s")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()