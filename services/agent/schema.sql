-- ClickHouse schema: ingest network flows directly from NATS
-- Run this once against your ClickHouse instance:
--   clickhouse-client --queries-file schema.sql

CREATE DATABASE IF NOT EXISTS nids;

-- NATS source table (ClickHouse reads from this subject in real-time)
CREATE TABLE IF NOT EXISTS nids.flows_nats (
    collected_at             String,
    flow_id                  String,
    src_ip                   String,
    dst_ip                   String,
    src_port                 UInt16,
    dst_port                 UInt16,
    protocol                 UInt8,
    ip_version               UInt8,
    bidirectional_first_seen_ms  UInt64,
    bidirectional_last_seen_ms   UInt64,
    bidirectional_duration_ms    UInt64,
    bidirectional_packets    UInt32,
    bidirectional_bytes      UInt64,
    src2dst_packets          UInt32,
    src2dst_bytes            UInt64,
    dst2src_packets          UInt32,
    dst2src_bytes            UInt64,
    application_name         String,
    application_category_name String,
    application_is_guessed   UInt8,
    application_confidence   Float32,
    requested_server_name    String,
    packets_per_second       Float64,
    bytes_per_second         Float64,
    -- statistical features (present when collector.statistical_analysis = true)
    bidirectional_min_ps     Float32,
    bidirectional_mean_ps    Float32,
    bidirectional_stddev_ps  Float32,
    bidirectional_max_ps     Float32,
    bidirectional_min_piat_ms    Float32,
    bidirectional_mean_piat_ms   Float32,
    bidirectional_stddev_piat_ms Float32,
    bidirectional_max_piat_ms    Float32,
    bidirectional_syn_packets    UInt32,
    bidirectional_ack_packets    UInt32,
    bidirectional_psh_packets    UInt32,
    bidirectional_rst_packets    UInt32,
    bidirectional_fin_packets    UInt32
)
ENGINE = NATS
SETTINGS
    nats_url      = 'nats://nats:4222',
    nats_subjects = 'flows.raw',
    nats_format   = 'MsgPack';

-- Persistent storage table
CREATE TABLE IF NOT EXISTS nids.flows (
    collected_at             DateTime,
    flow_id                  String,
    src_ip                   String,
    dst_ip                   String,
    src_port                 UInt16,
    dst_port                 UInt16,
    protocol                 UInt8,
    ip_version               UInt8,
    bidirectional_first_seen_ms  UInt64,
    bidirectional_last_seen_ms   UInt64,
    bidirectional_duration_ms    UInt64,
    bidirectional_packets    UInt32,
    bidirectional_bytes      UInt64,
    src2dst_packets          UInt32,
    src2dst_bytes            UInt64,
    dst2src_packets          UInt32,
    dst2src_bytes            UInt64,
    application_name         LowCardinality(String),
    application_category_name LowCardinality(String),
    application_is_guessed   UInt8,
    application_confidence   Float32,
    requested_server_name    String,
    packets_per_second       Float64,
    bytes_per_second         Float64,
    bidirectional_min_ps     Float32,
    bidirectional_mean_ps    Float32,
    bidirectional_stddev_ps  Float32,
    bidirectional_max_ps     Float32,
    bidirectional_min_piat_ms    Float32,
    bidirectional_mean_piat_ms   Float32,
    bidirectional_stddev_piat_ms Float32,
    bidirectional_max_piat_ms    Float32,
    bidirectional_syn_packets    UInt32,
    bidirectional_ack_packets    UInt32,
    bidirectional_psh_packets    UInt32,
    bidirectional_rst_packets    UInt32,
    bidirectional_fin_packets    UInt32
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(collected_at)
ORDER BY (collected_at, src_ip, dst_ip)
TTL collected_at + INTERVAL 90 DAY;

-- Materialized view: streams rows from NATS table into storage
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.flows_mv TO nids.flows AS
SELECT
    parseDateTime64BestEffort(collected_at) AS collected_at,
    flow_id,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    ip_version,
    bidirectional_first_seen_ms,
    bidirectional_last_seen_ms,
    bidirectional_duration_ms,
    bidirectional_packets,
    bidirectional_bytes,
    src2dst_packets,
    src2dst_bytes,
    dst2src_packets,
    dst2src_bytes,
    application_name,
    application_category_name,
    application_is_guessed,
    application_confidence,
    requested_server_name,
    packets_per_second,
    bytes_per_second,
    bidirectional_min_ps,
    bidirectional_mean_ps,
    bidirectional_stddev_ps,
    bidirectional_max_ps,
    bidirectional_min_piat_ms,
    bidirectional_mean_piat_ms,
    bidirectional_stddev_piat_ms,
    bidirectional_max_piat_ms,
    bidirectional_syn_packets,
    bidirectional_ack_packets,
    bidirectional_psh_packets,
    bidirectional_rst_packets,
    bidirectional_fin_packets
FROM nids.flows_nats;

-- All flows augmented with classifier output (BENIGN + threats).
-- Written by the orchestrator on every run; used for analysis and ML feedback.
CREATE TABLE IF NOT EXISTS nids.classified_flows (
    classified_at            DateTime  DEFAULT now(),
    flow_id                  String,
    src_ip                   String,
    dst_ip                   String,
    src_port                 UInt16,
    dst_port                 UInt16,
    protocol                 UInt8,
    collected_at             DateTime,
    bidirectional_duration_ms  UInt64,
    bidirectional_packets      UInt32,
    bidirectional_bytes        UInt64,
    packets_per_second         Float64,
    bytes_per_second           Float64,
    -- Classifier output
    label                    LowCardinality(String),  -- BENIGN | DoS | DDoS | PortScan | …
    confidence               Float32,
    probabilities            String,                  -- JSON: {"BENIGN":0.12,"DoS":0.88,…}
    is_threat                UInt8                    -- 0 = BENIGN, 1 = any threat
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(collected_at)
ORDER BY (collected_at, label, src_ip)
TTL collected_at + INTERVAL 30 DAY;

-- Raw output written directly by the Rust classifier gRPC service.
-- One row per flow per classify_batch RPC call; includes every label the classifier
-- evaluated (not just threats).  Useful for auditing classifier behaviour and
-- building ground-truth datasets without going through the orchestrator.
CREATE TABLE IF NOT EXISTS nids.classifier_alarms (
    alarm_id         UUID DEFAULT generateUUIDv4(),
    classified_at    DateTime DEFAULT now(),
    flow_id          String,
    src_ip           String,
    dst_ip           String,
    src_port         UInt16,
    dst_port         UInt16,
    protocol         UInt8,
    -- Classifier output
    label            LowCardinality(String),
    confidence       Float32,
    probabilities    String,  -- JSON: {"BENIGN":0.12,"DoS":0.88,...}
    is_threat        UInt8    -- 0 = BENIGN, 1 = threat
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(classified_at)
ORDER BY (classified_at, label, src_ip)
TTL classified_at + INTERVAL 30 DAY;

-- Threat-only events for alerting (subset of classified_flows where is_threat=1).
-- Kept separate so dashboards and PagerDuty rules can query a lean table.
CREATE TABLE IF NOT EXISTS nids.security_events (
    event_id              UUID    DEFAULT generateUUIDv4(),
    detected_at           DateTime DEFAULT now(),
    flow_id               String,
    src_ip                String,
    dst_ip                String,
    src_port              UInt16,
    dst_port              UInt16,
    protocol              UInt8,
    label                 LowCardinality(String),
    confidence            Float32,
    probabilities         String,
    bidirectional_packets UInt32,
    bidirectional_bytes   UInt64,
    bidirectional_duration_ms UInt64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(detected_at)
ORDER BY (detected_at, label, src_ip);
