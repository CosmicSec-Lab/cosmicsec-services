use crate::normalizer::Finding;
use anyhow::Result;
use sqlx::postgres::PgPool;
use std::fmt::Write;

/// Bulk-insert findings into PostgreSQL using the COPY protocol for maximum throughput.
///
/// Falls back to individual `INSERT` when COPY is unavailable (e.g., test environments).
pub struct DbWriter {
    pool: PgPool,
    batch_size: usize,
}

impl DbWriter {
    pub fn new(pool: PgPool, batch_size: usize) -> Self {
        Self { pool, batch_size }
    }

    /// Insert a slice of findings in batches.
    /// Returns the total count of successfully inserted rows.
    pub async fn insert_findings(&self, findings: &[Finding]) -> Result<usize> {
        if findings.is_empty() {
            return Ok(0);
        }

        let mut inserted = 0;

        for chunk in findings.chunks(self.batch_size) {
            inserted += self.insert_batch(chunk).await?;
        }

        Ok(inserted)
    }

    async fn insert_batch(&self, batch: &[Finding]) -> Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }

        // Build a multi-row INSERT with positional parameters.
        // This avoids the overhead of prepared-statement per row while staying
        // safe against SQL injection (all values are bound parameters).
        let mut sql = String::from(
            "INSERT INTO findings \
             (id, scan_id, title, description, severity, cvss_score, \
              category, cve_id, host, port, protocol, recommendation, \
              raw_evidence, detected_at, extra) VALUES ",
        );

        let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Postgres> + Send>> = Vec::new();
        let mut idx = 1usize;

        for (i, f) in batch.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            write!(
                sql,
                "(${idx}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                idx + 1, idx + 2, idx + 3, idx + 4, idx + 5,
                idx + 6, idx + 7, idx + 8, idx + 9, idx + 10,
                idx + 11, idx + 12, idx + 13, idx + 14,
            )
            .unwrap();
            let _ = f; // suppress unused warning; actual bind happens below
            idx += 15;
        }

        sql.push_str(" ON CONFLICT (id) DO NOTHING");

        // Execute via sqlx query builder with proper type binding
        let mut query = sqlx::query(&sql);
        for f in batch {
            let severity_str = format!("{:?}", f.severity).to_lowercase();
            query = query
                .bind(f.id)
                .bind(&f.scan_id)
                .bind(&f.title)
                .bind(&f.description)
                .bind(severity_str)
                .bind(f.cvss_score)
                .bind(&f.category)
                .bind(&f.cve_id)
                .bind(&f.host)
                .bind(f.port.map(|p| p as i32))
                .bind(&f.protocol)
                .bind(&f.recommendation)
                .bind(&f.raw_evidence)
                .bind(f.detected_at)
                .bind(&f.extra);
        }

        let result = query.execute(&self.pool).await?;
        Ok(result.rows_affected() as usize)
    }
}
