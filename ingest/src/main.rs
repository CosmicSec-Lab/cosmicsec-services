/// CosmicSec Ingest Binary
///
/// Parses security tool output files (nmap XML, nikto text, nuclei JSONL)
/// into a normalised JSON findings format.
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use tracing::{error, info};

mod error;
mod parsers;
mod schema;

use error::ParseError;
use schema::{Finding, IngestResult};

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Nmap,
    Nikto,
    Nuclei,
}

#[derive(Debug, Parser)]
#[command(
    name = "cosmicsec-ingest",
    about = "Parse security tool output and emit normalised JSON findings",
    version
)]
struct Args {
    /// Input file path (use `-` for stdin)
    #[arg(short, long)]
    input: String,

    /// Input format
    #[arg(short, long)]
    format: Format,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Target identifier (host / URL) to tag findings with
    #[arg(short, long, default_value = "unknown")]
    target: String,
}

fn parse_input(format: &Format, content: &str) -> Result<Vec<Finding>, ParseError> {
    match format {
        Format::Nmap => parsers::nmap::parse_nmap_xml(content),
        Format::Nikto => parsers::nikto::parse_nikto_text(content),
        Format::Nuclei => parsers::nuclei::parse_nuclei_jsonl(content),
    }
}

fn format_name(format: &Format) -> &'static str {
    match format {
        Format::Nmap => "nmap",
        Format::Nikto => "nikto",
        Format::Nuclei => "nuclei",
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cosmicsec_ingest=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let content = if args.input == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| {
                error!("Failed to read stdin: {}", e);
                std::process::exit(1);
            });
        buf
    } else {
        fs::read_to_string(&args.input).unwrap_or_else(|e| {
            error!("Failed to read input file '{}': {}", args.input, e);
            std::process::exit(1);
        })
    };

    info!("Parsing {} bytes of {} output", content.len(), format_name(&args.format));
    let start = Instant::now();

    let findings = match parse_input(&args.format, &content) {
        Ok(f) => f,
        Err(e) => {
            error!("Parse error: {}", e);
            std::process::exit(2);
        }
    };

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    info!("Parsed {} finding(s) in {:.2}ms", findings.len(), duration_ms);

    let result = IngestResult {
        findings,
        tool: format_name(&args.format).to_string(),
        target: args.target.clone(),
        duration_ms,
    };

    let json_out = match serde_json::to_string_pretty(&result) {
        Ok(s) => s,
        Err(e) => {
            error!("Serialisation error: {}", e);
            std::process::exit(3);
        }
    };

    match args.output {
        Some(path) => {
            fs::write(&path, &json_out).unwrap_or_else(|e| {
                error!("Failed to write output to '{}': {}", path.display(), e);
                std::process::exit(4);
            });
            info!("Results written to {}", path.display());
        }
        None => println!("{}", json_out),
    }
}
