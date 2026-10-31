import os
import re
import json
import time
import tempfile
import logging
from typing import AsyncGenerator, Tuple, List, Optional
from datetime import datetime
from fastapi import UploadFile

from backend.database import (
    bulk_insert_rows,
    bulk_insert_from_parquet_or_csv,
    get_db_connection,
    _db_lock,
)

logger = logging.getLogger("mitigata.ingestion")

# 50MB chunk size for streaming memory safety
STREAM_CHUNK_SIZE = 50 * 1024 * 1024
BATCH_INSERT_SIZE = 50000

# Regex patterns for common cybersecurity log formats (Syslog, RFC5424, VPC flow, CEF)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_REGEX = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)

def parse_line_to_record(line: str) -> Tuple[Optional[datetime], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], str]:
    """
    Parses a single log line (JSON, Syslog, VPC Flow, or custom log) into the normalized schema:
    (timestamp, source_ip, destination_ip, user_identity, host_name, event_type, status, raw_message)
    """
    raw_message = line.strip()
    if not raw_message:
        return None

    # 1. Attempt JSON parsing
    if raw_message.startswith("{") and raw_message.endswith("}"):
        try:
            data = json.loads(raw_message)
            ts_str = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            parsed_ts = None
            if ts_str:
                try:
                    parsed_ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                except Exception:
                    pass

            src_ip = data.get("source_ip") or data.get("src_ip") or data.get("src") or data.get("client_ip")
            dst_ip = data.get("destination_ip") or data.get("dest_ip") or data.get("dst") or data.get("server_ip")
            user = data.get("user_identity") or data.get("user") or data.get("username") or data.get("actor")
            host = data.get("host_name") or data.get("host") or data.get("hostname") or data.get("node")
            event = data.get("event_type") or data.get("event") or data.get("action") or data.get("method")
            status = data.get("status") or data.get("result") or data.get("response_code")

            return (
                parsed_ts,
                str(src_ip) if src_ip else None,
                str(dst_ip) if dst_ip else None,
                str(user) if user else None,
                str(host) if host else None,
                str(event) if event else None,
                str(status) if status else None,
                raw_message,
            )
        except Exception:
            pass

    # 2. Heuristic extraction for Syslog / VPC Flow / Plain Text
    ips = IP_REGEX.findall(raw_message)
    source_ip = ips[0] if len(ips) > 0 else None
    destination_ip = ips[1] if len(ips) > 1 else None

    # Extract Timestamp
    ts_match = TIMESTAMP_REGEX.search(raw_message)
    parsed_ts = None
    if ts_match:
        ts_str = ts_match.group(0)
        try:
            parsed_ts = datetime.fromisoformat(ts_str)
        except Exception:
            pass

    # Determine event type & status from common security keywords
    lower_line = raw_message.lower()
    event_type = "TRAFFIC"
    if "ssh" in lower_line or "login" in lower_line or "auth" in lower_line:
        event_type = "AUTHENTICATION"
    elif "dns" in lower_line:
        event_type = "DNS_QUERY"
    elif "kerberos" in lower_line or "tgs" in lower_line or "ticket" in lower_line:
        event_type = "KERBEROS_REQUEST"
    elif "http" in lower_line or "put" in lower_line or "post" in lower_line:
        event_type = "HTTP_REQUEST"
    elif "firewall" in lower_line or "drop" in lower_line or "accept" in lower_line:
        event_type = "FIREWALL_RULE"

    status = "ACCEPT"
    if "fail" in lower_line or "deny" in lower_line or "reject" in lower_line or "drop" in lower_line or "error" in lower_line:
        status = "DENY"

    return (
        parsed_ts or datetime.utcnow(),
        source_ip,
        destination_ip,
        None,
        None,
        event_type,
        status,
        raw_message,
    )

# Active job progress dictionary for real-time frontend monitoring
# job_id -> { status, filename, bytes_processed, total_bytes, percent, remaining_bytes, rows_ingested, elapsed_seconds }
active_ingestion_jobs = {}

def cleanup_old_jobs():
    """Keeps memory minimal by keeping only the most recent 30 jobs."""
    if len(active_ingestion_jobs) > 30:
        keys_to_remove = list(active_ingestion_jobs.keys())[:-30]
        for k in keys_to_remove:
            active_ingestion_jobs.pop(k, None)

async def stream_file_in_chunks(file: UploadFile, chunk_size: int = STREAM_CHUNK_SIZE) -> AsyncGenerator[bytes, None]:
    """Streams file upload bytes in fixed memory-safe blocks."""
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        yield chunk

async def process_streaming_ingest(file: UploadFile, job_id: Optional[str] = None) -> Tuple[int, int, float]:
    """
    Ingests an incoming file upload in a streaming, memory-safe manner.
    Keeps memory usage strictly minimal (<100MB) even with 2.1GB+ and 10GB+ files.
    Tracks real-time % processed, data volume, and remaining bytes.
    
    Returns:
        (ingested_rows, total_rows_in_db, duration_seconds)
    """
    start_time = time.perf_counter()
    filename = file.filename or "unknown.log"
    ext = os.path.splitext(filename)[1].lower()
    total_file_size = file.size or 0

    if job_id:
        cleanup_old_jobs()
        active_ingestion_jobs[job_id] = {
            "status": "processing",
            "filename": filename,
            "bytes_processed": 0,
            "total_bytes": total_file_size,
            "percent": 0.0,
            "remaining_bytes": total_file_size,
            "rows_ingested": 0,
            "elapsed_seconds": 0.0,
        }

    # Fast-Path for Standard CSV and JSON Files using DuckDB Native Vectorized C++ Engine
    # We spool the stream to a temporary disk location in 25MB chunks, avoiding RAM pressure.
    if ext in [".csv", ".tsv"]:
        temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
        try:
            bytes_spooled = 0
            with os.fdopen(temp_fd, "wb") as f_out:
                async for chunk in stream_file_in_chunks(file, chunk_size=25 * 1024 * 1024):
                    f_out.write(chunk)
                    bytes_spooled += len(chunk)
                    if job_id and total_file_size > 0:
                        pct = round(min(50.0, (bytes_spooled / total_file_size) * 50.0), 1)
                        active_ingestion_jobs[job_id] = {
                            "status": "processing",
                            "filename": filename,
                            "bytes_processed": bytes_spooled,
                            "total_bytes": total_file_size,
                            "percent": pct,
                            "remaining_bytes": max(0, total_file_size - bytes_spooled),
                            "rows_ingested": 0,
                            "elapsed_seconds": round(time.perf_counter() - start_time, 2),
                        }
            
            # Perform native C++ bulk append
            ingested_count = bulk_insert_from_parquet_or_csv(temp_path, "csv")
        except Exception as e:
            logger.warning(f"Native CSV ingest failed ({e}), falling back to line stream parser.")
            file.file.seek(0)
            ingested_count = await _process_line_by_line_stream(file, job_id, total_file_size, start_time)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    else:
        # Line-by-line streaming parser for .log, .txt, JSON-lines, Syslog, VPC logs
        ingested_count = await _process_line_by_line_stream(file, job_id, total_file_size, start_time)

    conn = get_db_connection()
    with _db_lock:
        total_rows = conn.execute("SELECT COUNT(*) FROM raw_logs;").fetchone()[0]

    duration = time.perf_counter() - start_time

    if job_id:
        active_ingestion_jobs[job_id] = {
            "status": "completed",
            "filename": filename,
            "bytes_processed": total_file_size or 0,
            "total_bytes": total_file_size or 0,
            "percent": 100.0,
            "remaining_bytes": 0,
            "rows_ingested": ingested_count,
            "elapsed_seconds": round(duration, 2),
        }

    return ingested_count, total_rows, duration

async def _process_line_by_line_stream(
    file: UploadFile,
    job_id: Optional[str] = None,
    total_file_size: int = 0,
    start_time: float = 0.0
) -> int:
    """Reads stream in 25MB blocks, parses line-by-line, updates progress, and bulk-inserts in 50k batches."""
    buffer = ""
    batch = []
    total_ingested = 0
    bytes_processed = 0

    if start_time == 0.0:
        start_time = time.perf_counter()

    async for chunk_bytes in stream_file_in_chunks(file, chunk_size=25 * 1024 * 1024):
        bytes_processed += len(chunk_bytes)
        text_chunk = chunk_bytes.decode("utf-8", errors="replace")
        buffer += text_chunk
        lines = buffer.split("\n")
        # Keep trailing incomplete line in buffer
        buffer = lines[-1]

        for line in lines[:-1]:
            record = parse_line_to_record(line)
            if record:
                batch.append(record)

            if len(batch) >= BATCH_INSERT_SIZE:
                total_ingested += bulk_insert_rows(batch)
                batch.clear()

        # Update real-time progress for frontend polling
        if job_id and total_file_size > 0:
            pct = round(min(99.0, (bytes_processed / total_file_size) * 100.0), 1)
            active_ingestion_jobs[job_id] = {
                "status": "processing",
                "filename": file.filename or "logs.log",
                "bytes_processed": bytes_processed,
                "total_bytes": total_file_size,
                "percent": pct,
                "remaining_bytes": max(0, total_file_size - bytes_processed),
                "rows_ingested": total_ingested,
                "elapsed_seconds": round(time.perf_counter() - start_time, 2),
            }

    # Process remaining buffer
    if buffer.strip():
        record = parse_line_to_record(buffer)
        if record:
            batch.append(record)

    if batch:
        total_ingested += bulk_insert_rows(batch)
        batch.clear()

    return total_ingested

