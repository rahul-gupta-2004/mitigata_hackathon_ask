import os
import re
import json
import time
import tempfile
import logging
from typing import AsyncGenerator, Tuple, List, Optional, Dict, Any
from datetime import datetime
from fastapi import UploadFile

from backend.database import (
    bulk_insert_rows,
    bulk_insert_from_parquet_or_csv,
    get_db_connection,
    _db_lock,
)

logger = logging.getLogger("mitigata.ingestion")

# Streaming and batching parameters for high-throughput, low-memory ingestion
STREAM_CHUNK_SIZE: int = 25 * 1024 * 1024  # 25 MB streaming blocks
BATCH_INSERT_SIZE: int = 50000  # 50,000 records per database bulk insert

# Regex patterns for common cybersecurity log formats (Syslog, RFC5424, VPC flow, CEF, Apache/Nginx)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_REGEX = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)

# Active ingestion job tracking dictionary for real-time frontend status polling
# Schema: job_id -> { status, filename, bytes_processed, total_bytes, percent, remaining_bytes, rows_ingested, elapsed_seconds }
active_ingestion_jobs: Dict[str, Dict[str, Any]] = {}

def cleanup_old_jobs(max_history: int = 30) -> None:
    """Keeps memory strictly bounded by retaining only the most recent N ingestion jobs."""
    if len(active_ingestion_jobs) > max_history:
        keys_to_remove = list(active_ingestion_jobs.keys())[:-max_history]
        for k in keys_to_remove:
            active_ingestion_jobs.pop(k, None)

def parse_line_to_record(
    line: str,
) -> Optional[Tuple[Optional[datetime], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], str]]:
    """
    Parses a single log line (Syslog, JSON, JSONL, VPC Flow, or custom plain-text log)
    into the normalized schema:
    (timestamp, source_ip, destination_ip, user_identity, host_name, event_type, status, raw_message)
    """
    raw_message = line.strip()
    if not raw_message:
        return None

    # 1. Attempt JSON / JSON-Lines parsing
    if raw_message.startswith("{") and raw_message.endswith("}"):
        try:
            data = json.loads(raw_message)
            if isinstance(data, dict):
                # Timestamp extraction
                ts_val = (
                    data.get("timestamp")
                    or data.get("time")
                    or data.get("@timestamp")
                    or data.get("datetime")
                    or data.get("ts")
                )
                parsed_ts: Optional[datetime] = None
                if ts_val:
                    try:
                        if isinstance(ts_val, (int, float)):
                            parsed_ts = datetime.utcfromtimestamp(ts_val)
                        else:
                            ts_str = str(ts_val).replace("Z", "+00:00")
                            parsed_ts = datetime.fromisoformat(ts_str)
                    except Exception:
                        parsed_ts = None

                src_ip = (
                    data.get("source_ip")
                    or data.get("src_ip")
                    or data.get("src")
                    or data.get("client_ip")
                    or data.get("sourceIp")
                )
                dst_ip = (
                    data.get("destination_ip")
                    or data.get("dest_ip")
                    or data.get("dst")
                    or data.get("server_ip")
                    or data.get("destIp")
                )
                user = (
                    data.get("user_identity")
                    or data.get("user")
                    or data.get("username")
                    or data.get("actor")
                    or data.get("userIdentity")
                )
                host = (
                    data.get("host_name")
                    or data.get("host")
                    or data.get("hostname")
                    or data.get("node")
                    or data.get("hostName")
                )
                event = (
                    data.get("event_type")
                    or data.get("event")
                    or data.get("action")
                    or data.get("method")
                    or data.get("protocol")
                    or data.get("eventType")
                )
                stat = (
                    data.get("status")
                    or data.get("result")
                    or data.get("response_code")
                    or data.get("action_status")
                )

                return (
                    parsed_ts or datetime.utcnow(),
                    str(src_ip) if src_ip is not None else None,
                    str(dst_ip) if dst_ip is not None else None,
                    str(user) if user is not None else None,
                    str(host) if host is not None else None,
                    str(event) if event is not None else "EVENT",
                    str(stat) if stat is not None else "ACCEPT",
                    raw_message,
                )
        except Exception:
            # Fall through to regex/heuristic parsing on JSON parse error
            pass

    # 2. Heuristic extraction for Syslog, VPC Flow, and Plain Text logs
    ips = IP_REGEX.findall(raw_message)
    source_ip = ips[0] if len(ips) > 0 else None
    destination_ip = ips[1] if len(ips) > 1 else None

    # Extract Timestamp via regex
    ts_match = TIMESTAMP_REGEX.search(raw_message)
    parsed_ts = None
    if ts_match:
        ts_str = ts_match.group(0)
        try:
            parsed_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            try:
                # Common syslog month/day format: 'Oct 31 03:12:04'
                current_year = datetime.utcnow().year
                parsed_ts = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            except Exception:
                parsed_ts = None

    # Classify event type from cybersecurity keywords
    lower_line = raw_message.lower()
    event_type = "TRAFFIC"
    if "ssh" in lower_line or "login" in lower_line or "auth" in lower_line or "sudo" in lower_line:
        event_type = "AUTHENTICATION"
    elif "dns" in lower_line or "query" in lower_line:
        event_type = "DNS_QUERY"
    elif "kerberos" in lower_line or "tgs" in lower_line or "ticket" in lower_line or "spn" in lower_line:
        event_type = "KERBEROS_REQUEST"
    elif "http" in lower_line or "put" in lower_line or "post" in lower_line or "get" in lower_line:
        event_type = "HTTP_REQUEST"
    elif "firewall" in lower_line or "drop" in lower_line or "accept" in lower_line or "vpc" in lower_line or "acl" in lower_line:
        event_type = "FIREWALL_RULE"

    # Classify status (ACCEPT vs DENY)
    status = "ACCEPT"
    if any(k in lower_line for k in ("fail", "deny", "reject", "drop", "error", "block")):
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

async def stream_file_in_chunks(
    file: UploadFile,
    chunk_size: int = STREAM_CHUNK_SIZE,
) -> AsyncGenerator[bytes, None]:
    """Streams file upload bytes in fixed memory-safe blocks."""
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        yield chunk

async def _process_line_by_line_stream(
    file: UploadFile,
    job_id: Optional[str] = None,
    total_file_size: int = 0,
    start_time: float = 0.0,
) -> int:
    """
    Reads stream in 25 MB blocks, parses line-by-line, updates active job progress,
    and bulk-inserts into DuckDB in batches of 50,000 records.
    Keeps memory usage strictly minimal (<500 MB) even for files up to 18 GB.
    """
    buffer = ""
    batch: List[tuple] = []
    total_ingested = 0
    bytes_processed = 0

    if start_time == 0.0:
        start_time = time.perf_counter()

    async for chunk_bytes in stream_file_in_chunks(file, chunk_size=STREAM_CHUNK_SIZE):
        bytes_processed += len(chunk_bytes)
        text_chunk = chunk_bytes.decode("utf-8", errors="replace")
        buffer += text_chunk
        lines = buffer.split("\n")
        # Retain trailing incomplete line in buffer for the next chunk
        buffer = lines[-1]

        for line in lines[:-1]:
            record = parse_line_to_record(line)
            if record is not None:
                batch.append(record)

            if len(batch) >= BATCH_INSERT_SIZE:
                total_ingested += bulk_insert_rows(batch)
                batch.clear()

        # Update real-time progress for frontend status polling
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

    # Process remaining line in buffer if present
    if buffer.strip():
        record = parse_line_to_record(buffer)
        if record is not None:
            batch.append(record)

    if batch:
        total_ingested += bulk_insert_rows(batch)
        batch.clear()

    return total_ingested

async def process_streaming_ingest(
    file: UploadFile,
    job_id: Optional[str] = None,
) -> Tuple[int, int, float]:
    """
    Ingests an incoming file upload in a streaming, memory-safe manner.
    Guarantees minimal RAM footprint (<500 MB) when processing massive files (up to 18 GB).
    Tracks real-time % processed, byte volume, remaining bytes, and row counts.

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

    # Check if compiled Rust ingestion binary exists for maximum throughput
    rust_bin = os.path.abspath("rust_ingestion/target/release/mitigata-ingest")
    if os.path.exists(rust_bin):
        temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
        try:
            bytes_spooled = 0
            with os.fdopen(temp_fd, "wb") as f_out:
                async for chunk in stream_file_in_chunks(file, chunk_size=STREAM_CHUNK_SIZE):
                    f_out.write(chunk)
                    bytes_spooled += len(chunk)
            
            import subprocess
            proc = subprocess.run(
                [rust_bin, temp_path, "--database", "mitigata_logs.duckdb", "--batch-size", "50000"],
                capture_output=True,
                text=True,
                check=False
            )
            ingested_count = 0
            for out_line in proc.stdout.splitlines():
                if "Rows Ingested (Run):" in out_line:
                    try:
                        ingested_count = int(out_line.split(":")[-1].strip().replace(",", ""))
                    except Exception:
                        pass
            if ingested_count == 0:
                await file.seek(0)
                ingested_count = await _process_line_by_line_stream(file, job_id, total_file_size, start_time)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    # Fast-Path for standard CSV and TSV files using DuckDB Native Vectorized C++ Engine
    # Spools the stream to a temporary disk location in 25 MB chunks to prevent RAM bloat.
    if ext in [".csv", ".tsv"]:
        temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
        try:
            bytes_spooled = 0
            with os.fdopen(temp_fd, "wb") as f_out:
                async for chunk in stream_file_in_chunks(file, chunk_size=STREAM_CHUNK_SIZE):
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
            await file.seek(0)
            ingested_count = await _process_line_by_line_stream(file, job_id, total_file_size, start_time)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    else:
        # Line-by-line streaming parser for .log, .txt, .json, .jsonl, Syslog, VPC logs
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
