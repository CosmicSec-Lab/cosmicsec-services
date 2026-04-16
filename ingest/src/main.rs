mod config;
mod db;
mod metrics;
mod normalizer;
mod parsers;
mod stream;

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use metrics::Metrics;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Shared application state passed to every Axum handler.
#[derive(Clone)]
struct AppState {
    metrics: Arc<Metrics>,
    start_time: std::time::Instant,
    version: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ---------------------------------------------------------------------------
    // Bootstrap: config, logging, tracing
    // ---------------------------------------------------------------------------
    dotenvy::dotenv().ok();

    let cfg = config::Config::from_env()?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cfg.log_level))
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        grpc_port = cfg.grpc_port,
        http_port = cfg.http_port,
        "CosmicSec Ingest Engine starting"
    );

    // ---------------------------------------------------------------------------
    // Database pool
    // ---------------------------------------------------------------------------
    let pool = PgPoolOptions::new()
        .max_connections(cfg.worker_concurrency as u32)
        .connect(&cfg.database_url)
        .await?;

    info!("PostgreSQL connection pool established");

    let writer = db::DbWriter::new(pool, cfg.db_batch_size);

    // ---------------------------------------------------------------------------
    // Metrics registry
    // ---------------------------------------------------------------------------
    let metrics = Arc::new(Metrics::new());

    // ---------------------------------------------------------------------------
    // Redis Streams consumer (background task)
    // ---------------------------------------------------------------------------
    {
        let cfg_clone = cfg.clone();
        let writer_clone = db::DbWriter::new(
            PgPoolOptions::new()
                .max_connections(cfg.worker_concurrency as u32)
                .connect(&cfg.database_url)
                .await?,
            cfg.db_batch_size,
        );
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            match stream::StreamConsumer::connect(&cfg_clone, writer_clone).await {
                Ok(mut consumer) => {
                    if let Err(e) = consumer.ensure_group().await {
                        tracing::warn!("Failed to ensure consumer group: {e}");
                    }
                    loop {
                        metrics_clone.active_workers.inc();
                        if let Err(e) = consumer.run().await {
                            tracing::error!("Stream consumer error: {e}");
                        }
                        metrics_clone.active_workers.dec();
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
                Err(e) => tracing::warn!("Redis unavailable — stream consumer disabled: {e}"),
            }
        });
    }

    // ---------------------------------------------------------------------------
    // HTTP health / metrics server
    // ---------------------------------------------------------------------------
    let state = AppState {
        metrics: metrics.clone(),
        start_time: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
    };

    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ready", get(ready_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(addr = %addr, "HTTP health server listening");

    axum::serve(listener, router).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "service": "cosmicsec-ingest",
        "version": state.version,
        "uptime_seconds": uptime,
    }))
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render();
    (StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], body)
}

async fn ready_handler(State(_state): State<AppState>) -> impl IntoResponse {
    // Readiness: can be extended with DB ping
    Json(json!({"ready": true}))
}
