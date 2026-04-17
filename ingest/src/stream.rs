use crate::{
    config::Config,
    db::DbWriter,
    parsers::parser_for_tool,
};
use anyhow::Result;
use redis::{aio::MultiplexedConnection, AsyncCommands, RedisError};
use tracing::{error, info, warn};

/// Redis Streams consumer that polls for raw scan data and dispatches it to
/// the appropriate parser and then writes findings to PostgreSQL.
pub struct StreamConsumer {
    conn: MultiplexedConnection,
    writer: DbWriter,
    stream_key: String,
    group: String,
    consumer_name: String,
}

impl StreamConsumer {
    pub async fn connect(config: &Config, writer: DbWriter) -> Result<Self> {
        let client = redis::Client::open(config.redis_url.as_str())?;
        let conn = client.get_multiplexed_tokio_connection().await?;

        let consumer_name = format!("ingest-{}", uuid::Uuid::new_v4());

        Ok(Self {
            conn,
            writer,
            stream_key: config.redis_stream_key.clone(),
            group: config.redis_consumer_group.clone(),
            consumer_name,
        })
    }

    /// Ensure the consumer group exists.  Idempotent — `MKSTREAM` creates the
    /// stream if it does not yet exist.
    pub async fn ensure_group(&mut self) -> Result<()> {
        let result: Result<(), RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.stream_key)
            .arg(&self.group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut self.conn)
            .await;

        match result {
            Ok(_) => info!(group = %self.group, "consumer group created"),
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                info!(group = %self.group, "consumer group already exists")
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Poll the stream for new messages, parse and persist findings.
    ///
    /// Runs indefinitely; call in a `tokio::spawn` background task.
    pub async fn run(&mut self) -> Result<()> {
        info!(stream = %self.stream_key, consumer = %self.consumer_name, "stream consumer started");

        loop {
            let messages: redis::streams::StreamReadReply = redis::cmd("XREADGROUP")
                .arg("GROUP")
                .arg(&self.group)
                .arg(&self.consumer_name)
                .arg("COUNT")
                .arg(10)
                .arg("BLOCK")
                .arg(5000)
                .arg("STREAMS")
                .arg(&self.stream_key)
                .arg(">")
                .query_async(&mut self.conn)
                .await
                .unwrap_or(redis::streams::StreamReadReply { keys: vec![] });

            for stream_key_entry in &messages.keys {
                for entry in &stream_key_entry.ids {
                    if let Err(e) = self.process_entry(entry).await {
                        error!(id = %entry.id, error = %e, "failed to process stream entry");
                    }

                    // Acknowledge message so it won't be redelivered
                    let _: Result<(), _> = self
                        .conn
                        .xack(&self.stream_key, &self.group, &[entry.id.as_str()])
                        .await;
                }
            }
        }
    }

    async fn process_entry(&self, entry: &redis::streams::StreamId) -> Result<()> {
        let scan_id = entry
            .map
            .get("scan_id")
            .and_then(|v| match v {
                redis::Value::Data(b) => std::str::from_utf8(b).ok().map(|s| s.to_owned()),
                _ => None,
            })
            .unwrap_or_default();

        let tool = entry
            .map
            .get("tool")
            .and_then(|v| match v {
                redis::Value::Data(b) => std::str::from_utf8(b).ok().map(|s| s.to_owned()),
                _ => None,
            })
            .unwrap_or_else(|| "generic_json".to_owned());

        let raw_data = match entry.map.get("data") {
            Some(redis::Value::Data(b)) => b.clone(),
            _ => {
                warn!(id = %entry.id, "stream entry missing 'data' field");
                return Ok(());
            }
        };

        info!(
            stream_id = %entry.id,
            scan_id = %scan_id,
            tool = %tool,
            bytes = raw_data.len(),
            "processing ingest message"
        );

        let parser = parser_for_tool(&tool);
        let findings = parser.parse(&scan_id, &raw_data)?;

        let count = self.writer.insert_findings(&findings).await?;
        info!(
            scan_id = %scan_id,
            tool = %tool,
            inserted = count,
            "findings inserted"
        );

        Ok(())
    }
}
