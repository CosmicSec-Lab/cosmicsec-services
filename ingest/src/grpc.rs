/// gRPC server for remote scan ingestion.
///
/// Implements the `IngestService` defined in `proto/ingest.proto`.

use crate::db::DbWriter;
use crate::normalizer::{Finding, Severity};
use crate::parsers::parser_for_tool;
use crate::AppState;
use std::pin::Pin;
use std::time::Instant;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub mod ingest_proto {
    tonic::include_proto!("cosmicsec.ingest.v1");
}

use ingest_proto::ingest_service_server::IngestService;
use ingest_proto::{
    FindingProto, IngestRequest, IngestResponse, StatusRequest, StatusResponse, ToolType,
};

type ResponseStream = Pin<Box<dyn Stream<Item = Result<FindingProto, Status>> + Send + 'static>>;

/// gRPC service implementation.
pub struct IngestSvc {
    pub db: DbWriter,
    pub state: AppState,
}

#[tonic::async_trait]
impl IngestService for IngestSvc {
    type StreamIngestStream = ResponseStream;

    async fn ingest_batch(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        let start = Instant::now();
        let inner = request.into_inner();

        if inner.raw_data.is_empty() {
            return Err(Status::invalid_argument("raw_data is empty"));
        }

        let tool_str = tool_type_from_i32(inner.tool);
        let parser = parser_for_tool(tool_str);

        let parse_start = Instant::now();
        let findings = parser
            .parse(&inner.scan_id, &inner.raw_data)
            .map_err(|e| Status::invalid_argument(format!("parse error: {e}")))?;
        let parse_errors = 0u32;
        let findings_parsed = findings.len() as u32;

        self.state
            .metrics
            .findings_parsed_total
            .inc_by(findings_parsed as u64);
        self.state
            .metrics
            .parse_duration_seconds
            .observe(parse_start.elapsed().as_secs_f64());

        let insert_start = Instant::now();
        let findings_inserted = self
            .db
            .insert_findings(&findings)
            .await
            .map_err(|e| Status::internal(format!("db write error: {e}")))?
            as u32;

        self.state
            .metrics
            .findings_inserted_total
            .inc_by(findings_inserted as u64);
        self.state
            .metrics
            .insert_duration_seconds
            .observe(insert_start.elapsed().as_secs_f64());

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(Response::new(IngestResponse {
            job_id: inner.job_id,
            scan_id: inner.scan_id,
            findings_parsed,
            findings_inserted,
            parse_errors,
            duration_ms,
            error_messages: vec![],
        }))
    }

    async fn stream_ingest(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<Self::StreamIngestStream>, Status> {
        let inner = request.into_inner();

        if inner.raw_data.is_empty() {
            return Err(Status::invalid_argument("raw_data is empty"));
        }

        let tool_str = tool_type_from_i32(inner.tool);
        let parser = parser_for_tool(tool_str);

        let findings = parser
            .parse(&inner.scan_id, &inner.raw_data)
            .map_err(|e| Status::invalid_argument(format!("parse error: {e}")))?;

        let stream = tokio_stream::iter(
            findings
                .into_iter()
                .map(|f| Ok(finding_to_proto(f)))
                .collect::<Vec<Result<FindingProto, Status>>>(),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let m = &self.state.metrics;
        let uptime = self.state.start_time.elapsed().as_secs();

        let parsed = m.findings_parsed_total.get();
        let errors = m.parse_errors_total.get();

        Ok(Response::new(StatusResponse {
            engine_version: self.state.version.to_string(),
            status: "ok".to_string(),
            findings_parsed_total: parsed,
            parse_errors_total: errors,
            avg_parse_rate_per_second: if uptime > 0 {
                parsed as f64 / uptime as f64
            } else {
                0.0
            },
            avg_insert_rate_per_second: if uptime > 0 {
                m.findings_inserted_total.get() as f64 / uptime as f64
            } else {
                0.0
            },
            uptime: format!("{uptime}s"),
        }))
    }
}

fn tool_type_from_i32(tool: i32) -> &'static str {
    match ToolType::try_from(tool).unwrap_or(ToolType::ToolUnknown) {
        ToolType::ToolNmap => "nmap",
        ToolType::ToolNuclei => "nuclei",
        ToolType::ToolNikto => "nikto",
        ToolType::ToolZap => "zap",
        ToolType::ToolSemgrep => "semgrep",
        ToolType::ToolTrivy => "trivy",
        ToolType::ToolGrype => "grype",
        ToolType::ToolGenericJson => "generic_json",
        ToolType::ToolUnknown => "generic_json",
    }
}

fn severity_to_i32(s: &Severity) -> i32 {
    match s {
        Severity::Critical => ingest_proto::Severity::Critical as i32,
        Severity::High => ingest_proto::Severity::High as i32,
        Severity::Medium => ingest_proto::Severity::Medium as i32,
        Severity::Low => ingest_proto::Severity::Low as i32,
        Severity::Info => ingest_proto::Severity::Info as i32,
        Severity::Unknown => ingest_proto::Severity::Unknown as i32,
    }
}

fn finding_to_proto(f: Finding) -> FindingProto {
    let extra = if let serde_json::Value::Object(map) = &f.extra {
        map.iter()
            .filter_map(|(k, v)| {
                if let serde_json::Value::String(s) = v {
                    Some((k.clone(), s.clone()))
                } else {
                    Some((k.clone(), v.to_string()))
                }
            })
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    FindingProto {
        id: f.id.to_string(),
        scan_id: f.scan_id,
        title: f.title,
        description: f.description,
        severity: severity_to_i32(&f.severity),
        cvss_score: f.cvss_score.unwrap_or(0.0),
        category: f.category,
        cve_id: f.cve_id.unwrap_or_default(),
        host: f.host,
        port: f.port.unwrap_or(0) as u32,
        protocol: f.protocol.unwrap_or_default(),
        recommendation: f.recommendation,
        raw_evidence: f.raw_evidence,
        detected_at: f.detected_at.to_rfc3339(),
        extra,
    }
}

/// Build the tonic gRPC server.
pub fn build_grpc_server(db: DbWriter, state: AppState) -> tonic::transport::server::Router {
    let svc = IngestSvc { db, state };
    tonic::transport::Server::builder()
        .add_service(ingest_proto::ingest_service_server::IngestServiceServer::new(svc))
}
