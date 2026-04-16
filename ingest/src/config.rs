use anyhow::Result;
use std::env;

/// Resolved runtime configuration for the ingest engine.
/// All fields are loaded from environment variables with safe defaults.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL connection string.
    pub database_url: String,

    /// Redis URL for the ingest stream consumer.
    pub redis_url: String,

    /// TCP port for the gRPC service.
    pub grpc_port: u16,

    /// TCP port for the HTTP health / metrics server.
    pub http_port: u16,

    /// Maximum concurrent ingest workers.
    pub worker_concurrency: usize,

    /// Number of findings to batch-insert per PostgreSQL COPY transaction.
    pub db_batch_size: usize,

    /// Redis stream key to consume raw scan output from.
    pub redis_stream_key: String,

    /// Consumer group name used for Redis Streams.
    pub redis_consumer_group: String,

    /// Log level string (`debug`, `info`, `warn`, `error`).
    pub log_level: String,

    /// OTLP endpoint for distributed traces (optional).
    pub otlp_endpoint: Option<String>,

    /// Feature flag: set to `"true"` to enable Rust ingest routing from the API Gateway.
    pub feature_enabled: bool,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if a required variable (`DATABASE_URL`) is absent.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env_require("DATABASE_URL")?,
            redis_url: env_default("REDIS_URL", "redis://127.0.0.1:6379"),
            grpc_port: env_default("GRPC_PORT", "50051").parse().unwrap_or(50051),
            http_port: env_default("HTTP_PORT", "8099").parse().unwrap_or(8099),
            worker_concurrency: env_default("WORKER_CONCURRENCY", "8").parse().unwrap_or(8),
            db_batch_size: env_default("DB_BATCH_SIZE", "500").parse().unwrap_or(500),
            redis_stream_key: env_default("REDIS_STREAM_KEY", "cosmicsec:ingest:raw"),
            redis_consumer_group: env_default("REDIS_CONSUMER_GROUP", "ingest-workers"),
            log_level: env_default("LOG_LEVEL", "info"),
            otlp_endpoint: env::var("OTLP_ENDPOINT").ok().filter(|s| !s.is_empty()),
            feature_enabled: env_default("COSMICSEC_USE_RUST_INGEST", "false") == "true",
        })
    }
}

fn env_require(key: &str) -> Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("Required environment variable '{}' is not set", key))
}

fn env_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}
