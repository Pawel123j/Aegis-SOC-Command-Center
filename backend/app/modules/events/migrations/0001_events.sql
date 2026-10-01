CREATE TABLE IF NOT EXISTS events
(
    event_id UUID,
    source_id UUID,
    dataset_id UUID,
    run_id UUID,
    timestamp DateTime64(6, 'UTC'),
    mode LowCardinality(String),
    source_name Nullable(String),
    source_type Nullable(String),
    source_ip Nullable(String),
    source_port Nullable(UInt32),
    destination_ip Nullable(String),
    destination_port Nullable(UInt32),
    user_id Nullable(String),
    user_name Nullable(String),
    user_realm Nullable(String),
    host_id Nullable(String),
    host_name Nullable(String),
    process_name Nullable(String),
    process_executable Nullable(String),
    command_line Nullable(String),
    event_category Nullable(String),
    event_type Nullable(String),
    event_action Nullable(String),
    event_outcome Nullable(String),
    event_severity Nullable(String),
    event_code Nullable(String),
    network_protocol Nullable(String),
    http_status_code Nullable(UInt32),
    document String,
    projection_version UInt64
)
ENGINE = ReplacingMergeTree(projection_version)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (dataset_id, source_id, timestamp, event_id)
