import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from backend.database import (
    get_db_connection,
    get_health_stats,
    get_sample_logs,
    init_schema,
    _db_lock,
)
from backend.ingestion import process_streaming_ingest
from backend.schemas import (
    HealthResponse,
    IngestResponse,
    SampleLogsResponse,
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
    title="Mitigata Cybersecurity Log Ingestion & Analytics API",
    version="1.0.0",
    description="Phase 1 Streaming Log Ingestion & DuckDB Vectorized Analytics Engine",
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

@app.get("/api/health", response_model=HealthResponse, summary="System & DuckDB Health Check")
async def health_check():
    """
    Returns system status, current DuckDB row counts, database file size, and memory consumption.
    """
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
    Accepts log file uploads (.log, .json, .csv) and streams them into DuckDB.
    Processes in memory-safe streaming blocks to guarantee RAM stays strictly minimal (<100MB)
    even when ingesting 2.1 GB+ or 10 GB+ log files.
    
    Supports live incremental appends without dropping existing DuckDB tables.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid filename."
        )

    logger.info(f"Beginning streaming ingestion for file: {file.filename} (job_id: {job_id})")
    
    try:
        # Seek to beginning in case read head was moved
        await file.seek(0)
        
        # Measure incoming file size if available from headers
        file_size = file.size or 0
        
        ingested_rows, total_rows, duration = await process_streaming_ingest(file, job_id=job_id)
        throughput = round(ingested_rows / duration, 2) if duration > 0 else float(ingested_rows)

        logger.info(
            f"Successfully ingested {ingested_rows} rows from {file.filename} "
            f"in {duration:.2f}s ({throughput:,.1f} rows/s). Total in DB: {total_rows}."
        )

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
    """
    Returns real-time data on bytes processed, % processed, rows ingested, and remaining bytes.
    """
    from backend.ingestion import active_ingestion_jobs
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
    """
    Returns the latest 50 (or user-defined limit) parsed log entries from DuckDB as JSON
    for frontend validation.
    """
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
    """
    Utility endpoint to truncate raw_logs table if the user wishes to reset and re-test.
    """
    try:
        conn = get_db_connection()
        with _db_lock:
            conn.execute("DELETE FROM raw_logs;")
        logger.info("Cleared raw_logs table in DuckDB.")
        return {"status": "success", "message": "All log records deleted from DuckDB."}
    except Exception as e:
        logger.error(f"Failed to clear logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing logs: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
