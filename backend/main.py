import logging
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Body, status, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.database import (
    get_db_connection,
    get_health_stats,
    get_sample_logs,
    init_schema,
    _db_lock,
)
from backend.ingestion import (
    process_streaming_ingest,
    active_ingestion_jobs,
)
from backend.schemas import (
    HealthResponse,
    IngestResponse,
    SampleLogsResponse,
)
from backend.agents.pipeline import (
    query_and_stamp_all_logs,
    build_attack_graph,
    export_react_flow_topology,
)
from backend.agents.risk_quantum import (
    compute_incident_risk_score,
    execute_quantum_lookahead,
)
from backend.agents.reporting import (
    generate_multilingual_narrative,
    generate_pdf_report,
    GENERATED_REPORTS_CACHE,
    SUPPORTED_LANGUAGES,
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("mitigata.backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes DuckDB on startup."""
    logger.info("Initializing DuckDB persistent storage at mitigata_logs.duckdb...")
    conn = get_db_connection()
    init_schema(conn)
    logger.info("DuckDB storage initialized successfully.")
    yield
    logger.info("Shutting down Mitigata backend...")

app = FastAPI(
    title="Mitigata Autonomous Cyber Defense & Ingestion Platform",
    version="2.0.0",
    description="Unified backend pipeline integrating Agents 1-5, DuckDB, NetworkX, Quantum QAOA, and Sarvam AI reporting.",
    lifespan=lifespan,
)

# CORS Middleware for seamless React integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory cache for the latest active graph and analysis state
current_graph_state: Dict[str, Any] = {}

# ---------------- Core Ingestion & Health Endpoints ----------------

@app.get("/api/health", response_model=HealthResponse, summary="System & DuckDB Health Check")
async def health_check():
    """Returns system status, DuckDB row counts, database size, and memory consumption."""
    try:
        stats = get_health_stats()
        return HealthResponse(**stats)
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database health check error: {str(e)}"
        )

@app.post("/api/ingest", response_model=IngestResponse, summary="Streaming Memory-Safe Log Ingestion")
async def ingest_logs(
    file: UploadFile = File(...),
    job_id: Optional[str] = Query(None, description="Optional client job ID for real-time progress tracking")
):
    """
    Accepts log file uploads (.log, .txt, .json, .jsonl, .csv, .tsv) and streams them into DuckDB.
    Processes in memory-safe streaming blocks keeping RAM minimal (<500 MB) for files up to 18 GB+.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid filename."
        )

    logger.info(f"Beginning streaming ingestion for file: {file.filename} (job_id: {job_id})")

    try:
        await file.seek(0)
        file_size = file.size or 0

        ingested_rows, total_rows, duration = await process_streaming_ingest(file, job_id=job_id)
        throughput = round(ingested_rows / duration, 2) if duration > 0 else float(ingested_rows)

        return IngestResponse(
            status="success",
            filename=file.filename,
            file_size_bytes=file_size,
            ingested_rows=ingested_rows,
            total_rows=total_rows,
            duration_seconds=round(duration, 3),
            throughput_rows_per_second=throughput,
        )
    except Exception as e:
        logger.error(f"Failed to ingest file {file.filename}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Streaming ingestion error: {str(e)}"
        )
    finally:
        await file.close()

@app.get("/api/ingest/progress", summary="Live Ingestion Progress")
async def get_ingest_progress(job_id: str = Query(..., description="Job identifier")):
    """Returns real-time data on bytes processed, % processed, rows ingested, and remaining bytes."""
    if job_id in active_ingestion_jobs:
        return active_ingestion_jobs[job_id]
    return {
        "status": "pending",
        "bytes_processed": 0,
        "total_bytes": 0,
        "percent": 0.0,
        "remaining_bytes": 0,
        "rows_ingested": 0,
        "elapsed_seconds": 0.0,
    }

@app.get("/api/logs/sample", response_model=SampleLogsResponse, summary="Fetch Latest Sample Logs")
async def get_sample_logs_endpoint(limit: int = Query(50, ge=1, le=500)):
    """Returns the latest N parsed log entries from DuckDB for frontend validation."""
    try:
        sample_logs = get_sample_logs(limit=limit)
        stats = get_health_stats()
        return SampleLogsResponse(
            total_in_db=stats["total_raw_logs"],
            returned_count=len(sample_logs),
            sample_logs=sample_logs,
        )
    except Exception as e:
        logger.error(f"Failed to fetch sample logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error querying sample logs from DuckDB: {str(e)}"
        )

@app.delete("/api/logs", summary="Clear DuckDB Log Table")
async def clear_logs():
    """Utility endpoint to truncate raw_logs table."""
    try:
        conn = get_db_connection()
        with _db_lock:
            conn.execute("DELETE FROM raw_logs;")
        current_graph_state.clear()
        logger.info("Cleared raw_logs table in DuckDB.")
        return {"status": "success", "message": "All log records deleted from DuckDB."}
    except Exception as e:
        logger.error(f"Failed to clear logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing logs: {str(e)}"
        )

# ---------------- Agent 1 & 2: Detection, Sigma Stamping & Graph Topology ----------------

@app.post("/api/analyze", summary="Execute Full Agent Pipeline (Detection, Graph, Risk, Quantum)")
async def run_full_pipeline_analysis(limit: int = Query(500, ge=10, le=5000)):
    """
    Executes Agent 1 (Sigma/MITRE stamping), Agent 2 (NetworkX topology construction),
    Agent 3 (Weighted Multi-Factor Heuristic Risk), and Agent 4 (Quantum Next-Hop Look-Ahead).
    """
    try:
        # Step 1: Agent 1 - Stamp raw logs from DuckDB with Sigma & MITRE taxonomy
        stamped_events = query_and_stamp_all_logs(limit=limit)
        threat_events = [e for e in stamped_events if e.get("is_threat")]

        # Step 2: Agent 2 - Construct NetworkX attack topology
        G = build_attack_graph(stamped_events)
        topology_data = export_react_flow_topology(G)
        current_graph_state["graph"] = G
        current_graph_state["topology"] = topology_data

        # Step 3: Agent 3 - Weighted Multi-Factor Risk Scoring with JEV validation
        risk_result = compute_incident_risk_score(threat_events or stamped_events, graph=G)

        # Step 4: Agent 4 - Quantum QAOA / Statevector look-ahead
        breach_node = "10.240.12.8"
        if threat_events:
            breach_node = threat_events[0].get("destination_ip") or threat_events[0].get("source_ip") or breach_node
        quantum_result = execute_quantum_lookahead(G, current_node=breach_node)

        return {
            "status": "success",
            "total_analyzed_logs": len(stamped_events),
            "threat_events_count": len(threat_events),
            "topology": topology_data,
            "risk_assessment": risk_result,
            "quantum_forecast": quantum_result,
        }
    except Exception as e:
        logger.error(f"Pipeline analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error in pipeline analysis: {str(e)}"
        )

@app.get("/api/graph/topology", summary="Fetch React Flow Attack Graph Topology")
async def get_graph_topology(refresh: bool = Query(False)):
    """Returns the topological graph tracking Host-Host, User-Host, and Host-User paths for React Flow."""
    try:
        if refresh or "topology" not in current_graph_state:
            stamped_events = query_and_stamp_all_logs(limit=500)
            G = build_attack_graph(stamped_events)
            topology_data = export_react_flow_topology(G)
            current_graph_state["graph"] = G
            current_graph_state["topology"] = topology_data

        return current_graph_state["topology"]
    except Exception as e:
        logger.error(f"Failed to generate topology: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Topology extraction error: {str(e)}"
        )

# ---------------- Agent 3: Risk Scoring & JEV Layer ----------------

class RiskRequest(BaseModel):
    events: Optional[List[Dict[str, Any]]] = None

@app.post("/api/risk-scores", summary="Compute Weighted Multi-Factor Risk Score & JEV Validation")
async def calculate_risk_scores(payload: Optional[RiskRequest] = None):
    """
    Computes a transparent Weighted Multi-Factor Heuristic score (0-100)
    with JEV (Justification/Verification) validation.
    """
    try:
        events = payload.events if payload and payload.events else None
        if not events:
            stamped = query_and_stamp_all_logs(limit=200)
            events = [e for e in stamped if e.get("is_threat")] or stamped

        G = current_graph_state.get("graph")
        if not G:
            G = build_attack_graph(events)

        risk_data = compute_incident_risk_score(events, graph=G)
        return risk_data
    except Exception as e:
        logger.error(f"Risk calculation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating risk score: {str(e)}"
        )

# ---------------- Agent 4: Quantum QAOA / Statevector Look-Ahead ----------------

class QuantumRequest(BaseModel):
    current_node: Optional[str] = "10.240.12.8"

@app.post("/api/quantum-predict", summary="Forecast Next-Hop Attack Vector via Qiskit QAOA Simulator")
async def predict_quantum_next_hop(payload: Optional[QuantumRequest] = None):
    """
    Extracts the graph adjacency matrix and executes Qiskit statevector simulation
    to predict next-hop attack paths and blast radius.
    """
    try:
        curr_node = payload.current_node if payload and payload.current_node else "10.240.12.8"
        G = current_graph_state.get("graph")
        if not G:
            stamped = query_and_stamp_all_logs(limit=200)
            G = build_attack_graph(stamped)
            current_graph_state["graph"] = G

        forecast = execute_quantum_lookahead(G, current_node=curr_node)
        return forecast
    except Exception as e:
        logger.error(f"Quantum look-ahead failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing quantum forecast: {str(e)}"
        )

# ---------------- Agent 5: Sarvam AI Multilingual Reporting & PDF Generation ----------------

class ReportGenerateRequest(BaseModel):
    incident_id: Optional[str] = "INC-8092"
    title: Optional[str] = "High-Entropy Kerberos SPN Burst & Lateral Exfiltration Attempt"
    severity: Optional[str] = "CRITICAL"
    score: Optional[float] = 9.3
    target_asset: Optional[str] = "Domain Controller (10.240.12.2)"
    predicted_next_hop: Optional[str] = "Customer Vault DB (10.240.64.19)"
    probability: Optional[float] = 0.88
    language: Optional[str] = "en"  # "en", "hi", "te", "ml"

@app.post("/api/reports/generate", summary="Generate Multilingual Executive Report via Sarvam AI & PDF")
async def generate_incident_report(payload: ReportGenerateRequest):
    """
    Synthesizes an executive incident brief via Sarvam AI (with Ollama fallback),
    generates a compiled PDF, and returns the report reference ID.
    """
    try:
        lang = payload.language if payload.language in SUPPORTED_LANGUAGES else "en"
        context = {
            "incident_id": payload.incident_id,
            "title": payload.title,
            "severity": payload.severity,
            "score": payload.score,
            "target_asset": payload.target_asset,
            "predicted_next_hop": payload.predicted_next_hop,
            "probability": payload.probability,
        }

        # Step 1: Synthesize narrative via Sarvam AI (or Ollama fallback)
        narrative_res = generate_multilingual_narrative(context, language=lang)
        narrative_text = narrative_res["narrative"]

        # Step 2: Compile executive PDF report
        report_id, _ = generate_pdf_report(context, narrative_text, language=lang)

        return {
            "status": "success",
            "report_id": report_id,
            "incident_id": payload.incident_id,
            "language": lang,
            "language_label": SUPPORTED_LANGUAGES.get(lang),
            "ai_provider": narrative_res["provider"],
            "narrative": narrative_text,
            "download_url": f"/api/reports/download/{report_id}",
            "created_at": narrative_res["timestamp"],
        }
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error compiling incident report: {str(e)}"
        )

@app.get("/api/reports/download/{report_id}", summary="Download Executive Incident Report PDF")
async def download_report_pdf(report_id: str):
    """Serves the compiled executive PDF incident report."""
    if report_id not in GENERATED_REPORTS_CACHE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found or expired. Please generate a report first."
        )

    cached = GENERATED_REPORTS_CACHE[report_id]
    pdf_bytes = cached["pdf_bytes"]

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Mitigata_Incident_Report_{report_id}.pdf"
        },
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
