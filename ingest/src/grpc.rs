/// gRPC server for remote scan ingestion.
///
/// Implements the `IngestService` defined in `proto/ingest.proto`.

use crate::db::DbWriter;
use crate::normalizer::{Finding, Severity};
use crate::parsers::parser_for_tool;
use crate::AppState;
use std::time::Instant;
use tonic::{Request, Response, Status};

pub mod ingest_proto {
    tonic::include_proto!("ingest");
}

use ingest_proto::ingest_service_server::IngestService;
use ingest_proto::{
    FindingProto, IngestRequest, IngestResponse, StatusRequest, StatusResponse, ToolType,
};

/// gRPC service implementation.
pub struct IngestSvc {
    pub db: DbWriter,
    pub state: AppState,
}

#[tonic::async_trait]
impl IngestService for IngestSvc {
    async fn ingest_batch(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        let start = Instant::now();
        let inner = request.into_inner();

        if inner.raw_data.is_empty() {
            return Err(Status::invalid_argument("raw_data is empty"));
        }

        let tool_str = tool_type_to_str(inner.tool);
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

        let tool_str = tool_type_to_str(inner.tool);
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

fn tool_type_to_str(tool: ToolType) -> &'static str {
    match tool {
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

fn severity_to_proto(s: &Severity) -> ingest_proto::Severity {
    match s {
        Severity::Critical => ingest_proto::Severity::Critical,
        Severity::High => ingest_proto::Severity::High,
        Severity::Medium => ingest_proto::Severity::Medium,
        Severity::Low => ingest_proto::Severity::Low,
        Severity::Info => ingest_proto::Severity::Info,
        Severity::Unknown => ingest_proto::Severity::Unknown,
    }
}

fn finding_to_proto(f: Finding) -> FindingProto {
    FindingProto {
        id: f.id.to_string(),
        scan_id: f.scan_id,
        title: f.title,
        description: f.description,
        severity: severity_to_proto(&f.severity),
        cvss_score: f.cvss_score.unwrap_or(0.0),
        category: f.category,
        cve_id: f.cve_id.unwrap_or_default(),
        host: f.host,
        port: f.port.unwrap_or(0) as u32,
        protocol: f.protocol.unwrap_or_default(),
        recommendation: f.recommendation,
        raw_evidence: f.raw_evidence,
        detected_at: f.detected_at.to_rfc3339(),
        extra: serde_json::to_string(&f.extra).unwrap_or_default(),
    }
}

/// Build the tonic gRPC server.
pub fn build_grpc_server(db: DbWriter, state: AppState) -> tonic::transport::Server {
    let svc = IngestSvc { db, state };
    tonic::transport::Server::builder()
        .add_service(ingest_proto::ingest_service_server::IngestServiceServer::new(svc))
}
