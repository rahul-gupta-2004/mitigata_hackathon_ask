import os
import duckdb
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime

DATABASE_FILE = os.path.abspath("mitigata_logs.duckdb")
_db_lock = threading.Lock()
_conn: Optional[duckdb.DuckDBPyConnection] = None

def get_db_connection() -> duckdb.DuckDBPyConnection:
    """Returns a shared, thread-safe DuckDB connection."""
    global _conn
    if _conn is None:
        with _db_lock:
            if _conn is None:
                _conn = duckdb.connect(database=DATABASE_FILE, read_only=False)
                # Optimize DuckDB engine settings for large-scale log analytics
                _conn.execute("PRAGMA threads=4;")
                _conn.execute("PRAGMA memory_limit='8GB';")
                _conn.execute("PRAGMA preserve_insertion_order=false;")
                init_schema(_conn)
    return _conn

def init_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Creates the normalized raw_logs table if it does not already exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_logs (
            timestamp TIMESTAMP,
            source_ip VARCHAR,
            destination_ip VARCHAR,
            user_identity VARCHAR,
            host_name VARCHAR,
            event_type VARCHAR,
            status VARCHAR,
            raw_message TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_raw_logs_timestamp ON raw_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_raw_logs_source_ip ON raw_logs(source_ip);
        CREATE INDEX IF NOT EXISTS idx_raw_logs_event_type ON raw_logs(event_type);
    """)

def get_health_stats() -> Dict[str, Any]:
    """Retrieves system status, current DuckDB row counts, table size, and memory stats."""
    conn = get_db_connection()
    with _db_lock:
        row_count = conn.execute("SELECT COUNT(*) FROM raw_logs;").fetchone()[0]
    
    db_size = os.path.getsize(DATABASE_FILE) if os.path.exists(DATABASE_FILE) else 0
    db_size_mb = round(db_size / (1024 * 1024), 2)
    
    process_memory_mb = 0.0
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    process_memory_mb = round(int(parts[1]) / 1024, 2)
                    break
    except Exception:
        pass

    return {
        "status": "healthy",
        "duckdb_version": duckdb.__version__,
        "database_file": DATABASE_FILE,
        "database_size_bytes": db_size,
        "database_size_mb": db_size_mb,
        "total_raw_logs": row_count,
        "process_memory_mb": process_memory_mb,
    }

def get_sample_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns the latest N parsed log entries from DuckDB for frontend validation."""
    conn = get_db_connection()
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
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()

    results = []
    for row in rows:
        record = {}
        for col_name, val in zip(columns, row):
            if isinstance(val, datetime):
                record[col_name] = val.isoformat()
            else:
                record[col_name] = val
        results.append(record)
    return results

def bulk_insert_rows(rows: List[tuple]) -> int:
    """Inserts a batch of log tuples directly into DuckDB using executemany with thread-safety."""
    if not rows:
        return 0
    conn = get_db_connection()
    with _db_lock:
        conn.executemany("""
            INSERT INTO raw_logs (
                timestamp, source_ip, destination_ip, user_identity,
                host_name, event_type, status, raw_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, rows)
    return len(rows)

def bulk_insert_from_parquet_or_csv(file_path: str, format_type: str) -> int:
    """
    Directly ingests a file using DuckDB's vectorized native C++ engine.
    """
    conn = get_db_connection()
    with _db_lock:
        count_before = conn.execute("SELECT COUNT(*) FROM raw_logs;").fetchone()[0]
        if format_type == "csv":
            conn.execute(f"""
                INSERT INTO raw_logs
                SELECT 
                    TRY_CAST(timestamp AS TIMESTAMP),
                    TRY_CAST(source_ip AS VARCHAR),
                    TRY_CAST(destination_ip AS VARCHAR),
                    TRY_CAST(user_identity AS VARCHAR),
                    TRY_CAST(host_name AS VARCHAR),
                    TRY_CAST(event_type AS VARCHAR),
                    TRY_CAST(status AS VARCHAR),
                    TRY_CAST(raw_message AS TEXT)
                FROM read_csv_auto('{file_path}', header=true, sample_size=20000);
            """)
        elif format_type == "json":
            conn.execute(f"""
                INSERT INTO raw_logs
                SELECT 
                    TRY_CAST(timestamp AS TIMESTAMP),
                    TRY_CAST(source_ip AS VARCHAR),
                    TRY_CAST(destination_ip AS VARCHAR),
                    TRY_CAST(user_identity AS VARCHAR),
                    TRY_CAST(host_name AS VARCHAR),
                    TRY_CAST(event_type AS VARCHAR),
                    TRY_CAST(status AS VARCHAR),
                    TRY_CAST(raw_message AS TEXT)
                FROM read_json_auto('{file_path}');
            """)
        count_after = conn.execute("SELECT COUNT(*) FROM raw_logs;").fetchone()[0]
        return count_after - count_before
