use crate::types::ParsedLogRecord;
use duckdb::{params, Connection, Result};
use std::path::Path;

/// Database controller managing schema creation, PRAGMA settings, and bulk transactions
pub struct DatabaseManager {
    conn: Connection,
}

impl DatabaseManager {
    /// Opens or creates the DuckDB database and configures performance PRAGMAs
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Vectorized performance optimizations
        conn.execute("PRAGMA threads=4;", [])?;
        conn.execute("PRAGMA memory_limit='8GB';", [])?;
        conn.execute("PRAGMA preserve_insertion_order=false;", [])?;

        let manager = Self { conn };
        manager.init_schema()?;
        Ok(manager)
    }

    /// Creates the normalized raw_logs table and indexes if not already present
    pub fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS raw_logs (
                timestamp VARCHAR,
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
            "#,
        )?;
        Ok(())
    }

    /// Bulk-inserts a batch of records using DuckDB's high-speed Appender C++ API
    pub fn bulk_insert_batch(&mut self, batch: &[ParsedLogRecord]) -> Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }

        // Fast-path: DuckDB Appender API (direct columnar append with minimal memory overhead)
        let mut appender = self.conn.appender("raw_logs")?;
        for record in batch {
            appender.append_row(params![
                record.timestamp.as_deref(),
                record.source_ip.as_deref(),
                record.destination_ip.as_deref(),
                record.user_identity.as_deref(),
                record.host_name.as_deref(),
                &record.event_type,
                &record.status,
                &record.raw_message,
            ])?;
        }
        appender.flush()?;
        Ok(batch.len())
    }

    /// Retrieves the current total row count in the raw_logs table
    pub fn count_rows(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM raw_logs;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }
}
