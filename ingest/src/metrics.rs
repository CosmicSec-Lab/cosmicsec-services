use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

/// Central metrics registry for the ingest engine.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Mutex<Registry>>,

    /// Total number of findings parsed successfully.
    pub findings_parsed_total: Counter,

    /// Total number of parse errors encountered.
    pub parse_errors_total: Counter,

    /// Total number of findings inserted into PostgreSQL.
    pub findings_inserted_total: Counter,

    /// Total number of DB insert errors.
    pub insert_errors_total: Counter,

    /// Duration of individual parse operations (seconds).
    pub parse_duration_seconds: Histogram,

    /// Duration of DB batch insert operations (seconds).
    pub insert_duration_seconds: Histogram,

    /// Current number of active ingest workers.
    pub active_workers: Gauge,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let findings_parsed_total = Counter::default();
        let parse_errors_total = Counter::default();
        let findings_inserted_total = Counter::default();
        let insert_errors_total = Counter::default();
        let parse_duration_seconds =
            Histogram::new(exponential_buckets(0.001, 2.0, 12));
        let insert_duration_seconds =
            Histogram::new(exponential_buckets(0.001, 2.0, 12));
        let active_workers = Gauge::default();

        registry.register(
            "findings_parsed",
            "Total findings parsed from scan-tool output",
            findings_parsed_total.clone(),
        );
        registry.register(
            "parse_errors",
            "Total parse errors",
            parse_errors_total.clone(),
        );
        registry.register(
            "findings_inserted",
            "Total findings inserted into PostgreSQL",
            findings_inserted_total.clone(),
        );
        registry.register(
            "insert_errors",
            "Total DB insert errors",
            insert_errors_total.clone(),
        );
        registry.register(
            "parse_duration_seconds",
            "Parse operation duration in seconds",
            parse_duration_seconds.clone(),
        );
        registry.register(
            "insert_duration_seconds",
            "DB batch insert duration in seconds",
            insert_duration_seconds.clone(),
        );
        registry.register(
            "active_workers",
            "Currently active ingest worker tasks",
            active_workers.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            findings_parsed_total,
            parse_errors_total,
            findings_inserted_total,
            insert_errors_total,
            parse_duration_seconds,
            insert_duration_seconds,
            active_workers,
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let registry = self.registry.lock().unwrap();
        let mut buf = String::new();
        encode(&mut buf, &registry).unwrap_or_default();
        buf
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
