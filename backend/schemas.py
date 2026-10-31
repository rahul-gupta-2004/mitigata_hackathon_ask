from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class LogRecord(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_identity: Optional[str] = None
    host_name: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None
    raw_message: Optional[str] = None

class IngestResponse(BaseModel):
    status: str
    filename: str
    file_size_bytes: int
    ingested_rows: int
    total_rows: int
    duration_seconds: float
    throughput_rows_per_second: float

class HealthResponse(BaseModel):
    status: str
    duckdb_version: str
    database_file: str
    database_size_bytes: int
    database_size_mb: float
    total_raw_logs: int
    process_memory_mb: float

class SampleLogsResponse(BaseModel):
    total_in_db: int
    returned_count: int
    sample_logs: List[LogRecord]
