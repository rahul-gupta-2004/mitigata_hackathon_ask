# Mitigata High-Performance Rust Ingestion Engine

An ultra high-throughput, low-memory streaming log parser and DuckDB bulk ingestion CLI engineered for the **Mitigata** cybersecurity platform.

This engine streams multi-gigabyte and multi-terabyte raw telemetry (`.log`, `.txt`, `.json`, `.jsonl`, Syslog, VPC Flow logs) in memory-safe buffered chunks (<200 MB RAM) and utilizes DuckDB's vectorized C++ `Appender` API to ingest logs into the shared database (`mitigata_logs.duckdb`) for downstream Python and React analytics.

---

## Features

- **Blazing Throughput**: Ingests hundreds of thousands of records per second via zero-allocation buffered scanning and DuckDB columnar `Appender` transactions.
- **Strictly Bounded RAM (< 200 MB)**: Uses an 8 MB `BufReader` ring-buffer with fixed 50,000-row batch commits, allowing 18 GB+ log files to be ingested without memory exhaustion.
- **Universal Multi-Format Parser**:
  - **JSON & JSON-Lines**: Automatically extracts timestamps, source/dest IPs, user identities, hosts, event types, and statuses.
  - **Syslog (RFC 3164/5424) & VPC Flow**: Regex extraction for IPv4/IPv6 addresses, ISO-8601 timestamps, and syslog dates.
  - **Categorization**: Classifies events (`AUTHENTICATION`, `DNS_QUERY`, `KERBEROS_REQUEST`, `HTTP_REQUEST`, `FIREWALL_RULE`, `TRAFFIC`) and containment actions (`ACCEPT`, `DENY`).
- **Real-Time Progress & Formatted Time Telemetry**:
  - Dynamically calculates throughput (rows/sec, MB/s) and display **Estimated Time to Arrival (ETA)** in `00h 02m 14s` format.
  - Displays **Overall Processing Time** in formatted `HH:MM:SS` upon completion.

---

## Database Schema

Automatically initializes or connects to `mitigata_logs.duckdb`:

```sql
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
```

---

## Compilation Instructions

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (version 1.75+ recommended)
- Standard C++ compiler for DuckDB native bundled build (`build-essential` on Debian/Ubuntu, Xcode on macOS)

### 1. Build Optimized Release Binary

```bash
cd rust_ingestion
cargo build --release
```

The resulting high-performance standalone binary will be available at:
```bash
./target/release/mitigata-ingest
```

---

## Usage

### Direct Execution
```bash
# Ingest raw security events into default mitigata_logs.duckdb
./target/release/mitigata-ingest /path/to/vpc_flow_telemetry.log

# Or run via cargo
cargo run --release -- /path/to/security_events.jsonl
```

### Command-Line Options
```text
Usage: mitigata-ingest <file_path> [--database <db_path>] [--batch-size <size>]

Arguments:
  <file_path>           Path to raw .log, .txt, .json, or .jsonl telemetry file
  --database <db_path>  Target DuckDB file (default: mitigata_logs.duckdb)
  --batch-size <size>   Batch size for bulk append (default: 50,000 rows)
  --help, -h            Show this help manual
```

### Custom Database and Batch Size
```bash
./target/release/mitigata-ingest /var/log/suricata.log --database ../mitigata_logs.duckdb --batch-size 100000
```

---

## Example Terminal Output

```text
================================================================================
  __  __ ___ _____ ___ ____    _  _____  _      ___ _   _  ____ _____ ____ _____ 
 |  \/  |_ _|_   _|_ _/ ___|  / \|_   _|/ \    |_ _| \ | |/ ___| ____/ ___|_   _|
 | |\/| || |  | |  | | |  _  / _ \ | | / _ \    | ||  \| | |  _|  _| \___ \ | |  
 | |  | || |  | |  | | |_| |/ ___ \| |/ ___ \   | || |\  | |_| | |___ ___) || |  
 |_|  |_|___| |_| |___\____/_/   \_\_/_/   \_\ |___|_| \_|\____|_____|____/ |_|  
================================================================================
 Ultra High-Throughput Cyber Telemetry & DuckDB Ingestion Engine
================================================================================

[CONFIG] Target File:     "security_events_10gb.log"
[CONFIG] DuckDB Database: "mitigata_logs.duckdb"
[CONFIG] Batch Size:      50000 rows/transaction
[CONFIG] Total File Size: 10.42 GB (11,188,290,144 bytes)

[DATABASE] DuckDB connection initialized with 8GB RAM limit and 4 threads.
[DATABASE] Schema initialized: raw_logs table ready.

>>> Starting streaming ingestion loop...

[PROGRESS]  48.6% |    2,850,000 rows | 5.06 GB / 10.42 GB |    242,110 rows/s | Elapsed: 00m 11s | ETA: 00m 12s

================================================================================
 INGESTION COMPLETED SUCCESSFULLY
================================================================================
 Input File:                 "security_events_10gb.log"
 Target Database:            "mitigata_logs.duckdb" (table: raw_logs)
 Total File Size:            10.42 GB (11,188,290,144 bytes)
 Rows Ingested (Run):        5,842,100
 Total Records in Database:  5,842,100
 Overall Processing Time:    00m 23s (23.412s total)
 Expected Time Remaining:    00s (Completed)
 Ingestion Throughput:       249,534 rows/sec (455.12 MB/s)
 Memory Footprint:           < 180 MB RAM (streaming BufReader + Appender flush)
================================================================================
```
