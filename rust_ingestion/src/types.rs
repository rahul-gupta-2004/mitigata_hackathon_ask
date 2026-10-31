use serde::{Deserialize, Serialize};

/// Normalized schema representation for the DuckDB `raw_logs` table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedLogRecord {
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub user_identity: Option<String>,
    pub host_name: Option<String>,
    pub event_type: String,
    pub status: String,
    pub raw_message: String,
}

/// Statistics and execution metrics reported during and after log ingestion
#[derive(Debug, Clone, Default)]
pub struct IngestionMetrics {
    pub total_bytes_file: u64,
    pub bytes_processed: u64,
    pub rows_parsed: u64,
    pub batches_committed: u64,
    pub parse_errors: u64,
}
