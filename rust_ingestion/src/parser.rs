use crate::types::ParsedLogRecord;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

static IP_REGEX: OnceLock<Regex> = OnceLock::new();
static TIMESTAMP_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_ip_regex() -> &'static Regex {
    IP_REGEX.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("Invalid IP regex"))
}

fn get_timestamp_regex() -> &'static Regex {
    TIMESTAMP_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
            .expect("Invalid timestamp regex")
    })
}

/// Fast line parser supporting JSON/JSONL, Syslog, VPC Flow logs, and plain text
pub fn parse_line(line: &str) -> Option<ParsedLogRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. High-speed JSON / JSONL parsing path
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
            let timestamp = map
                .get("timestamp")
                .or_else(|| map.get("time"))
                .or_else(|| map.get("@timestamp"))
                .or_else(|| map.get("datetime"))
                .or_else(|| map.get("ts"))
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else if let Some(n) = v.as_i64() {
                        DateTime::<Utc>::from_timestamp(n, 0).map(|dt| dt.to_rfc3339())
                    } else if let Some(f) = v.as_f64() {
                        DateTime::<Utc>::from_timestamp(f as i64, 0).map(|dt| dt.to_rfc3339())
                    } else {
                        None
                    }
                })
                .or_else(|| Some(Utc::now().to_rfc3339()));

            let source_ip = map
                .get("source_ip")
                .or_else(|| map.get("src_ip"))
                .or_else(|| map.get("src"))
                .or_else(|| map.get("client_ip"))
                .or_else(|| map.get("sourceIp"))
                .and_then(|v| v.as_str().map(ToString::to_string));

            let destination_ip = map
                .get("destination_ip")
                .or_else(|| map.get("dest_ip"))
                .or_else(|| map.get("dst"))
                .or_else(|| map.get("server_ip"))
                .or_else(|| map.get("destIp"))
                .and_then(|v| v.as_str().map(ToString::to_string));

            let user_identity = map
                .get("user_identity")
                .or_else(|| map.get("user"))
                .or_else(|| map.get("username"))
                .or_else(|| map.get("actor"))
                .or_else(|| map.get("userIdentity"))
                .and_then(|v| v.as_str().map(ToString::to_string));

            let host_name = map
                .get("host_name")
                .or_else(|| map.get("host"))
                .or_else(|| map.get("hostname"))
                .or_else(|| map.get("node"))
                .or_else(|| map.get("hostName"))
                .and_then(|v| v.as_str().map(ToString::to_string));

            let event_type = map
                .get("event_type")
                .or_else(|| map.get("event"))
                .or_else(|| map.get("action"))
                .or_else(|| map.get("method"))
                .or_else(|| map.get("protocol"))
                .or_else(|| map.get("eventType"))
                .and_then(|v| v.as_str().map(ToString::to_string))
                .unwrap_or_else(|| "EVENT".to_string());

            let status = map
                .get("status")
                .or_else(|| map.get("result"))
                .or_else(|| map.get("response_code"))
                .or_else(|| map.get("action_status"))
                .and_then(|v| v.as_str().map(ToString::to_string))
                .unwrap_or_else(|| "ACCEPT".to_string());

            return Some(ParsedLogRecord {
                timestamp,
                source_ip,
                destination_ip,
                user_identity,
                host_name,
                event_type,
                status,
                raw_message: trimmed.to_string(),
            });
        }
    }

    // 2. Heuristic extraction for Syslog, RFC5424, VPC Flow, and Plain Text
    let ip_re = get_ip_regex();
    let mut ips = ip_re.find_iter(trimmed);
    let source_ip = ips.next().map(|m| m.as_str().to_string());
    let destination_ip = ips.next().map(|m| m.as_str().to_string());

    let ts_re = get_timestamp_regex();
    let timestamp = ts_re
        .find(trimmed)
        .map(|m| m.as_str().to_string())
        .or_else(|| Some(Utc::now().to_rfc3339()));

    let lower = trimmed.to_ascii_lowercase();

    // Event categorization
    let event_type = if lower.contains("ssh") || lower.contains("login") || lower.contains("auth") || lower.contains("sudo") {
        "AUTHENTICATION".to_string()
    } else if lower.contains("dns") || lower.contains("query") {
        "DNS_QUERY".to_string()
    } else if lower.contains("kerberos") || lower.contains("tgs") || lower.contains("ticket") || lower.contains("spn") {
        "KERBEROS_REQUEST".to_string()
    } else if lower.contains("http") || lower.contains("put") || lower.contains("post") || lower.contains("get") {
        "HTTP_REQUEST".to_string()
    } else if lower.contains("firewall") || lower.contains("drop") || lower.contains("accept") || lower.contains("vpc") || lower.contains("acl") {
        "FIREWALL_RULE".to_string()
    } else {
        "TRAFFIC".to_string()
    };

    // Status classification
    let status = if lower.contains("fail")
        || lower.contains("deny")
        || lower.contains("reject")
        || lower.contains("drop")
        || lower.contains("error")
        || lower.contains("block")
    {
        "DENY".to_string()
    } else {
        "ACCEPT".to_string()
    };

    Some(ParsedLogRecord {
        timestamp,
        source_ip,
        destination_ip,
        user_identity: None,
        host_name: None,
        event_type,
        status,
        raw_message: trimmed.to_string(),
    })
}
