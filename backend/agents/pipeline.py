import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import networkx as nx

from backend.database import get_db_connection, _db_lock

logger = logging.getLogger("mitigata.agents.pipeline")

# ==============================================================================
# Agent 1: Detection & MITRE ATT&CK / Sigma Rule Stamping Engine
# ==============================================================================

SIGMA_RULES = [
    {
        "id": "SIGMA-001",
        "name": "Kerberoasting SPN Ticket Request Burst",
        "mitre_id": "T1558.003",
        "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "base_weight": 0.92,
        "keywords": ["kerberos", "spn", "tgs", "ticket", "encryption type 0x17"],
        "ports": [88, 135, 389],
    },
    {
        "id": "SIGMA-002",
        "name": "Privileged Remote Service Lateral Movement",
        "mitre_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop & SSH Traversal",
        "tactic": "Lateral Movement",
        "severity": "HIGH",
        "base_weight": 0.85,
        "keywords": ["ssh", "rdp", "winrm", "remote desktop", "pam_unix", "session opened"],
        "ports": [22, 3389, 5985, 5986],
    },
    {
        "id": "SIGMA-003",
        "name": "High-Frequency Authentication Brute Force",
        "mitre_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "base_weight": 0.78,
        "keywords": ["failed password", "authentication failure", "invalid credentials", "login deny"],
        "ports": [22, 443, 3389, 80],
    },
    {
        "id": "SIGMA-004",
        "name": "Network Discovery & LDAP Reconnaissance",
        "mitre_id": "T1046",
        "technique_name": "Network Service Discovery / Domain Recon",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "base_weight": 0.65,
        "keywords": ["ldap", "port scan", "syn sweep", "directory sweep", "nmap"],
        "ports": [389, 636, 135, 445],
    },
    {
        "id": "SIGMA-005",
        "name": "Unauthorized Egress & Exfiltration Over Alternative Port",
        "mitre_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "severity": "CRITICAL",
        "base_weight": 0.95,
        "keywords": ["customer vault", "egress block", "large payload", "dns tunneling", "data dump"],
        "ports": [5432, 27017, 3306, 443, 53],
    },
    {
        "id": "SIGMA-006",
        "name": "Public-Facing Application Exploitation / SSRF Header Smuggling",
        "mitre_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity": "CRITICAL",
        "base_weight": 0.90,
        "keywords": ["imds", "header smuggling", "reverse proxy", "169.254.169.254", "sqli", "rce"],
        "ports": [80, 443, 8080],
    },
]

def stamp_single_event(log: Dict[str, Any]) -> Dict[str, Any]:
    """Matches a normalized log entry against Sigma rules and stamps MITRE ATT&CK taxonomy."""
    raw = (log.get("raw_message") or "").lower()
    event_type = (log.get("event_type") or "").upper()
    status = (log.get("status") or "").upper()
    port = log.get("port") or 0

    best_match: Optional[Dict[str, Any]] = None
    highest_weight = 0.0

    for rule in SIGMA_RULES:
        # Check keyword matches
        keyword_hit = any(kw in raw for kw in rule["keywords"])
        port_hit = port in rule["ports"] if port else False
        event_hit = (rule["tactic"].upper() in event_type) or (rule["mitre_id"].split(".")[0] in event_type)

        if keyword_hit or (port_hit and event_hit) or (status == "DENY" and keyword_hit):
            if rule["base_weight"] > highest_weight:
                highest_weight = rule["base_weight"]
                best_match = rule

    stamped = dict(log)
    if best_match:
        stamped["is_threat"] = True
        stamped["sigma_rule_id"] = best_match["id"]
        stamped["rule_name"] = best_match["name"]
        stamped["mitre_id"] = best_match["mitre_id"]
        stamped["technique_name"] = best_match["technique_name"]
        stamped["tactic"] = best_match["tactic"]
        stamped["severity"] = best_match["severity"]
        stamped["threat_weight"] = best_match["base_weight"]
        stamped["justification"] = f"Triggered {best_match['name']} ({best_match['mitre_id']}) based on behavioral heuristic indicators."
    else:
        stamped["is_threat"] = False
        stamped["sigma_rule_id"] = None
        stamped["rule_name"] = "Normal Traffic"
        stamped["mitre_id"] = None
        stamped["technique_name"] = "Authorized Enterprise Flow"
        stamped["tactic"] = "Normal Operation"
        stamped["severity"] = "LOW"
        stamped["threat_weight"] = 0.10
        stamped["justification"] = "Standard baseline telemetry."

    return stamped

def query_and_stamp_all_logs(limit: int = 500) -> List[Dict[str, Any]]:
    """Queries DuckDB raw_logs table and stamps every entry with MITRE ATT&CK metadata."""
    conn = get_db_connection()
    logs_to_stamp = []

    try:
        with _db_lock:
            cursor = conn.execute(f"""
                SELECT 
                    timestamp,
                    source_ip,
                    destination_ip,
                    user_identity,
                    host_name,
                    event_type,
                    status,
                    raw_message
                FROM raw_logs
                ORDER BY timestamp DESC NULLS LAST
                LIMIT {int(limit)};
            """)
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()

        for row in rows:
            record = {}
            for col_name, val in zip(cols, row):
                if isinstance(val, datetime):
                    record[col_name] = val.isoformat()
                else:
                    record[col_name] = val
            logs_to_stamp.append(record)
    except Exception as e:
        logger.warning(f"Error querying DuckDB: {e}. Using fallback sample logs.")

    # Fallback telemetry if database is empty
    if not logs_to_stamp:
        logs_to_stamp = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": "198.51.100.24",
                "destination_ip": "10.240.4.10",
                "user_identity": "external-adversary",
                "host_name": "edge-proxy-01",
                "event_type": "HTTP_REQUEST",
                "status": "ACCEPT",
                "raw_message": "Reverse proxy header smuggling with IMDS 169.254.169.254 endpoint attempt",
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": "10.240.4.10",
                "destination_ip": "10.240.12.8",
                "user_identity": "svc_ansible",
                "host_name": "app-gateway-01",
                "event_type": "KERBEROS_REQUEST",
                "status": "ACCEPT",
                "raw_message": "High-entropy SPN Kerberos ticket request burst targeting TGS tickets",
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": "10.240.12.8",
                "destination_ip": "10.240.12.2",
                "user_identity": "admin_audit",
                "host_name": "auth-ad-01",
                "event_type": "AUTHENTICATION",
                "status": "ACCEPT",
                "raw_message": "Privileged LDAP directory reconnaissance sweep across security groups",
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": "10.240.12.2",
                "destination_ip": "10.240.64.19",
                "user_identity": "root",
                "host_name": "cust-vault-primary",
                "event_type": "FIREWALL_RULE",
                "status": "DENY",
                "raw_message": "Blocked unauthorized egress connection to customer vault port 5432",
            },
        ]

    stamped_events = [stamp_single_event(l) for l in logs_to_stamp]
    return stamped_events

# ==============================================================================
# Agent 2: Topological Graph Construction & Multi-Branch Path Analysis
# ==============================================================================

def build_attack_graph(stamped_events: List[Dict[str, Any]]) -> nx.DiGraph:
    """
    Constructs a directed NetworkX graph tracking Host-Host, User-Host, and Host-User
    interactions chronologically, identifying critical lateral movement paths.
    """
    G = nx.DiGraph()

    for idx, event in enumerate(stamped_events):
        src = event.get("source_ip") or "unknown_src"
        dst = event.get("destination_ip") or "unknown_dst"
        user = event.get("user_identity")
        event_type = event.get("event_type") or "TRAFFIC"
        is_threat = event.get("is_threat", False)
        severity = event.get("severity") or "LOW"
        weight = event.get("threat_weight", 0.1)

        # Ensure source and destination nodes exist
        if not G.has_node(src):
            G.add_node(
                src,
                type="host",
                ip=src,
                compromise_level="breached" if is_threat else "normal",
                risk_score=round(weight * 100, 1),
                mitre_tactics=[event.get("tactic")] if is_threat else [],
            )
        else:
            if is_threat:
                G.nodes[src]["compromise_level"] = "breached"
                G.nodes[src]["risk_score"] = max(G.nodes[src]["risk_score"], round(weight * 100, 1))
                if event.get("tactic") and event.get("tactic") not in G.nodes[src]["mitre_tactics"]:
                    G.nodes[src]["mitre_tactics"].append(event.get("tactic"))

        if not G.has_node(dst):
            G.add_node(
                dst,
                type="host",
                ip=dst,
                compromise_level="targeted" if is_threat else "normal",
                risk_score=round(weight * 85, 1),
                mitre_tactics=[event.get("tactic")] if is_threat else [],
            )
        else:
            if is_threat:
                G.nodes[dst]["risk_score"] = max(G.nodes[dst]["risk_score"], round(weight * 85, 1))

        # Include User node if available
        if user:
            user_node = f"user:{user}"
            if not G.has_node(user_node):
                G.add_node(
                    user_node,
                    type="user",
                    username=user,
                    compromise_level="compromised" if is_threat else "normal",
                    risk_score=round(weight * 90, 1),
                    mitre_tactics=[event.get("tactic")] if is_threat else [],
                )
            G.add_edge(
                user_node,
                src,
                relation="AUTH_FROM",
                timestamp=event.get("timestamp"),
                weight=weight,
            )

        # Host-to-Host directed edge
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += weight
            G[src][dst]["count"] += 1
            if is_threat:
                G[src][dst]["is_threat"] = True
                G[src][dst]["severity"] = severity
                G[src][dst]["mitre_id"] = event.get("mitre_id")
        else:
            G.add_edge(
                src,
                dst,
                id=f"edge-{idx}",
                relation="NETWORK_FLOW",
                protocol=event_type,
                timestamp=event.get("timestamp"),
                is_threat=is_threat,
                severity=severity,
                mitre_id=event.get("mitre_id"),
                weight=weight,
                count=1,
            )

    return G

def export_react_flow_topology(graph: nx.DiGraph) -> Dict[str, Any]:
    """
    Serializes the NetworkX graph into React Flow format with layout coordinates,
    node styling, edge metadata, and path metrics.
    """
    nodes = []
    edges = []

    # Simple hierarchical layout positioning
    positions = {
        "198.51.100.24": (80, 180),
        "10.240.4.10": (280, 180),
        "10.240.12.8": (480, 140),
        "10.240.12.2": (680, 140),
        "10.240.64.19": (860, 220),
    }

    step_x = 180
    curr_x = 100
    curr_y = 120

    for idx, (node_id, data) in enumerate(graph.nodes(data=True)):
        if node_id in positions:
            pos_x, pos_y = positions[node_id]
        else:
            pos_x = curr_x + (idx * step_x) % 700
            pos_y = curr_y + ((idx * 80) % 250)

        label = data.get("ip") or data.get("username") or node_id
        is_user = data.get("type") == "user"

        nodes.append({
            "id": node_id,
            "type": "customThreatNode",
            "position": {"x": pos_x, "y": pos_y},
            "data": {
                "id": node_id,
                "label": label,
                "nodeType": data.get("type", "host"),
                "compromiseLevel": data.get("compromise_level", "normal"),
                "riskScore": data.get("risk_score", 15.0),
                "mitreTactics": data.get("mitre_tactics", []),
            },
        })

    for u, v, data in graph.edges(data=True):
        edge_id = data.get("id") or f"e-{u}-{v}"
        is_threat = data.get("is_threat", False)
        severity = data.get("severity", "LOW")

        edges.append({
            "id": edge_id,
            "source": u,
            "target": v,
            "animated": is_threat,
            "style": {
                "stroke": "#ef4444" if severity == "CRITICAL" else "#f59e0b" if is_threat else "#10b981",
                "strokeWidth": 2.5 if is_threat else 1.5,
            },
            "data": {
                "protocol": data.get("protocol", "TCP"),
                "timestamp": data.get("timestamp"),
                "mitreId": data.get("mitre_id"),
                "severity": severity,
                "weight": round(data.get("weight", 0.1), 2),
                "count": data.get("count", 1),
            },
        })

    # Find highest risk critical path
    critical_paths = []
    try:
        sources = [n for n, d in graph.in_degree() if d == 0]
        targets = [n for n, d in graph.out_degree() if d == 0]
        for s in sources:
            for t in targets:
                if nx.has_path(graph, s, t):
                    for path in nx.all_shortest_paths(graph, s, t):
                        critical_paths.append(path)
    except Exception:
        pass

    return {
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "critical_paths_found": len(critical_paths),
            "critical_paths": critical_paths[:3],
        },
    }
