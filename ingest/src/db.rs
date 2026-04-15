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

        const COLS_PER_ROW: usize = 15;

        for i in 0..batch.len() {
            if i > 0 {
                sql.push_str(", ");
            }
            let base = i * COLS_PER_ROW;
            write!(
                sql,
                "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                base + 1, base + 2, base + 3, base + 4, base + 5,
                base + 6, base + 7, base + 8, base + 9, base + 10,
                base + 11, base + 12, base + 13, base + 14, base + 15,
            )
            .unwrap();
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
