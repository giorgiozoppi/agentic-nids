-- ClickHouse schema for the classifier service.
-- Applied automatically by the docker-compose ClickHouse initdb mount.

CREATE DATABASE IF NOT EXISTS nids;

-- Raw output written directly by the Rust classifier gRPC service.
-- One row per flow per classify_batch RPC call.
CREATE TABLE IF NOT EXISTS nids.classifier_alarms (
    alarm_id         UUID         DEFAULT generateUUIDv4(),
    classified_at    DateTime     DEFAULT now(),
    flow_id          String,
    src_ip           String,
    dst_ip           String,
    src_port         UInt16,
    dst_port         UInt16,
    protocol         UInt8,
    label            LowCardinality(String),
    confidence       Float32,
    probabilities    String,   -- JSON: {"BENIGN":0.12,"DoS":0.88,...}
    is_threat        UInt8     -- 0 = BENIGN, 1 = threat
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(classified_at)
ORDER BY (classified_at, label, src_ip)
TTL classified_at + INTERVAL 30 DAY;
