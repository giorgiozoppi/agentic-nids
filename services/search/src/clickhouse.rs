// ClickHouse backend.
//
// Implements the QueryTranslator trait for ClickHouse SQL dialect and wires it
// into a CSP actor pool (ClickHouseBackend).
//
// Separation of concerns
// ──────────────────────
//   query.rs              ← database-agnostic DSL types + QueryTranslator trait
//   clickhouse.rs (this)  ← ClickHouse SQL compiler + connection pool
//
// To target a different database, implement QueryTranslator for it and pass
// the new translator to TrafficBackend::new().  Nothing else changes.

use std::sync::Arc;

use anyhow::Context;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::backend::SearchBackend;
use crate::pool::{Pool, CHANNEL_CAP};
use crate::query::{
    Aggregation, Filter, FilterOp, FilterValue, Join, JoinKind, Metric, OrderBy,
    QueryTranslator, SortDir, TrafficRequest, TrafficResponse, validate_request,
};

// ---------------------------------------------------------------------------
// ClickHouse translator — SQL dialect, identifier quoting, response parsing
// ---------------------------------------------------------------------------

/// Compiles the database-agnostic OLAP DSL to ClickHouse SQL.
///
/// Rules:
///   - All identifiers are backtick-quoted (`\`col\``).
///   - Table names with a schema part ("nids.flows") quote each part separately.
///   - String values are single-quoted with `\'` escaping.
///   - UNION ALL is wrapped in a subquery so ORDER BY / LIMIT applies globally.
pub struct ClickHouseTranslator;

impl QueryTranslator for ClickHouseTranslator {
    fn compile(&self, req: &TrafficRequest, limit: usize) -> anyhow::Result<String> {
        Ok(compile_request(req, limit))
    }

    fn parse_response(
        &self,
        raw:        Value,
        row_limit:  usize,
        collection: String,
        compiled:   String,
    ) -> anyhow::Result<TrafficResponse> {
        let meta = raw["meta"]
            .as_array()
            .context("missing 'meta' in ClickHouse response")?;

        let columns: Vec<String> = meta
            .iter()
            .map(|m| m["name"].as_str().unwrap_or("").to_string())
            .collect();

        let data = raw["data"]
            .as_array()
            .context("missing 'data' in ClickHouse response")?;

        let rows: Vec<Value> = data.iter().cloned().collect();
        let row_count = rows.len();

        Ok(TrafficResponse {
            collection,
            columns,
            truncated: row_count >= row_limit,
            row_count,
            rows,
            compiled_query: compiled,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal command
// ---------------------------------------------------------------------------

pub struct ChCmd {
    pub req:        TrafficRequest,
    pub row_limit:  usize,
    pub translator: Arc<dyn QueryTranslator>,
    pub reply:      oneshot::Sender<anyhow::Result<TrafficResponse>>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

pub struct ClickHouseBackend {
    pool:       Pool<ChCmd>,
    row_limit:  usize,
    translator: Arc<dyn QueryTranslator>,
}

impl ClickHouseBackend {
    /// Spawn `workers` actor tasks.  `translator` converts requests to SQL and
    /// parses responses; swap it for a different `QueryTranslator` to target
    /// another database without changing this struct.
    pub fn new(
        config:     ChConfig,
        workers:    usize,
        row_limit:  usize,
        translator: Arc<dyn QueryTranslator>,
    ) -> Arc<Self> {
        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel::<ChCmd>(CHANNEL_CAP);
            tokio::spawn(ch_worker(rx, config.clone()));
            senders.push(tx);
        }
        Arc::new(Self {
            pool: Pool::from_senders(senders),
            row_limit,
            translator,
        })
    }
}

impl SearchBackend for ClickHouseBackend {
    type Req  = TrafficRequest;
    type Resp = TrafficResponse;

    async fn search(&self, req: TrafficRequest) -> anyhow::Result<TrafficResponse> {
        validate_request(&req)?;
        let (tx, rx) = oneshot::channel();
        self.pool.dispatch(ChCmd {
            req,
            row_limit:  self.row_limit,
            translator: Arc::clone(&self.translator),
            reply:      tx,
        }).await?;
        rx.await.context("worker dropped reply channel")?
    }
}

// ---------------------------------------------------------------------------
// Worker (owns its own reqwest::Client — no sharing)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ChConfig {
    pub base_url: String,
    pub database: String,
    pub user:     String,
    pub password: String,
}

async fn ch_worker(mut rx: mpsc::Receiver<ChCmd>, config: ChConfig) {
    let client = Client::builder()
        .pool_max_idle_per_host(4)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    while let Some(ChCmd { req, row_limit, translator, reply }) = rx.recv().await {
        let result = execute(&client, &config, req, row_limit, translator).await;
        let _ = reply.send(result);
    }
}

async fn execute(
    client:     &Client,
    config:     &ChConfig,
    req:        TrafficRequest,
    row_limit:  usize,
    translator: Arc<dyn QueryTranslator>,
) -> anyhow::Result<TrafficResponse> {
    let effective_limit = req.limit.unwrap_or(row_limit).min(row_limit);

    let sql        = translator.compile(&req, effective_limit)?;
    let body       = format!("{sql} FORMAT JSONCompact");
    let url        = format!("{}/", config.base_url);
    let collection = req.collection.clone();

    let resp = client
        .post(&url)
        .query(&[("database", &config.database)])
        .basic_auth(&config.user, Some(&config.password))
        .body(body)
        .send()
        .await
        .context("ClickHouse request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text   = resp.text().await.unwrap_or_default();
        anyhow::bail!("ClickHouse {status}: {text}");
    }

    let raw: Value = resp.json().await.context("parse ClickHouse response")?;
    translator.parse_response(raw, row_limit, collection, sql)
}

// ---------------------------------------------------------------------------
// ClickHouse SQL compiler (private to this module)
// ---------------------------------------------------------------------------

fn compile_request(req: &TrafficRequest, limit: usize) -> String {
    let order_by     = compile_order_by(&req.order_by);
    let limit_clause = format!(" LIMIT {limit}");

    if req.union_all.is_empty() {
        let body = compile_select_body_with_joins(
            &req.collection, &req.dimensions, &req.metrics, &req.filters, &req.joins,
        );
        format!("{body}{order_by}{limit_clause}")
    } else {
        // UNION ALL: joins only apply to the primary branch
        let mut branches: Vec<String> = Vec::with_capacity(1 + req.union_all.len());
        branches.push(compile_select_body_with_joins(
            &req.collection, &req.dimensions, &req.metrics, &req.filters, &req.joins,
        ));
        for u in &req.union_all {
            let col = u.collection.as_deref().unwrap_or(&req.collection);
            branches.push(compile_select_body(col, &u.dimensions, &u.metrics, &u.filters));
        }
        format!(
            "SELECT * FROM ({}) AS _union{order_by}{limit_clause}",
            branches.join(" UNION ALL ")
        )
    }
}

fn compile_select_body(
    collection: &str,
    dimensions: &[String],
    metrics:    &[Metric],
    filters:    &[Filter],
) -> String {
    compile_select_body_with_joins(collection, dimensions, metrics, filters, &[])
}

fn compile_select_body_with_joins(
    collection: &str,
    dimensions: &[String],
    metrics:    &[Metric],
    filters:    &[Filter],
    joins:      &[Join],
) -> String {
    let mut cols: Vec<String> = dimensions.iter().map(|d| quote_ident(d)).collect();
    for m in metrics {
        let expr = match m.agg {
            Aggregation::Count         => format!("COUNT({})", if m.field == "*" { "*".into() } else { quote_ident(&m.field) }),
            Aggregation::CountDistinct => format!("COUNT(DISTINCT {})", quote_ident(&m.field)),
            Aggregation::Sum           => format!("SUM({})",  quote_ident(&m.field)),
            Aggregation::Avg           => format!("AVG({})",  quote_ident(&m.field)),
            Aggregation::Min           => format!("MIN({})",  quote_ident(&m.field)),
            Aggregation::Max           => format!("MAX({})",  quote_ident(&m.field)),
        };
        cols.push(format!("{} AS {}", expr, quote_ident(&m.alias)));
    }

    let select = if cols.is_empty() { "*".into() } else { cols.join(", ") };

    // JOIN clauses
    let join_clauses: String = joins.iter().map(|j| compile_join(j)).collect();

    // WHERE: outer filters + any join-specific filters
    let mut all_filters: Vec<String> = filters.iter().map(compile_filter).collect();
    for j in joins {
        let alias = join_alias(j);
        for f in &j.filters {
            all_filters.push(format!("{}.{}", alias, compile_filter(f)));
        }
    }
    let where_clause = if all_filters.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", all_filters.join(" AND "))
    };

    let group_by = if !metrics.is_empty() && !dimensions.is_empty() {
        format!(" GROUP BY {}", dimensions.iter().map(|d| quote_ident(d)).collect::<Vec<_>>().join(", "))
    } else {
        String::new()
    };

    format!("SELECT {select} FROM {collection}{join_clauses}{where_clause}{group_by}")
}

fn join_alias(j: &Join) -> String {
    if let Some(ref a) = j.alias {
        quote_ident(a)
    } else {
        // Default alias = last segment of "schema.table"
        let last = j.collection.split('.').last().unwrap_or(&j.collection);
        quote_ident(last)
    }
}

fn compile_join(j: &Join) -> String {
    let kind = match j.kind {
        JoinKind::Inner => "INNER JOIN",
        JoinKind::Left  => "LEFT JOIN",
        JoinKind::Right => "RIGHT JOIN",
        JoinKind::Full  => "FULL OUTER JOIN",
        JoinKind::Cross => "CROSS JOIN",
    };

    let alias   = join_alias(j);
    let on_cond = j.on.iter().map(|c| {
        format!("{} = {}.{}", quote_ident(&c.left), alias, quote_ident(&c.right))
    }).collect::<Vec<_>>().join(" AND ");

    if matches!(j.kind, JoinKind::Cross) || on_cond.is_empty() {
        format!(" {kind} {} AS {alias}", j.collection)
    } else {
        format!(" {kind} {} AS {alias} ON {on_cond}", j.collection)
    }
}

fn compile_order_by(order_by: &[OrderBy]) -> String {
    if order_by.is_empty() { return String::new(); }
    let parts: Vec<String> = order_by.iter().map(|o| {
        let dir = match o.dir { SortDir::Asc => "ASC", SortDir::Desc => "DESC" };
        format!("{} {}", quote_ident(&o.field), dir)
    }).collect();
    format!(" ORDER BY {}", parts.join(", "))
}

fn compile_filter(f: &Filter) -> String {
    let col = quote_ident(&f.field);
    match f.op {
        FilterOp::IsNull    => format!("{col} IS NULL"),
        FilterOp::IsNotNull => format!("{col} IS NOT NULL"),
        FilterOp::In | FilterOp::NotIn => {
            let kw   = if matches!(f.op, FilterOp::In) { "IN" } else { "NOT IN" };
            let vals = match &f.value {
                FilterValue::List(items) => items.iter().map(quote_value).collect::<Vec<_>>().join(", "),
                other                    => quote_value(other),
            };
            format!("{col} {kw} ({vals})")
        }
        _ => {
            let op_str = match f.op {
                FilterOp::Eq    => "=",
                FilterOp::Ne    => "!=",
                FilterOp::Gt    => ">",
                FilterOp::Gte   => ">=",
                FilterOp::Lt    => "<",
                FilterOp::Lte   => "<=",
                FilterOp::Like  => "LIKE",
                FilterOp::ILike => "ILIKE",
                _ => unreachable!(),
            };
            format!("{col} {op_str} {}", quote_value(&f.value))
        }
    }
}

/// Quote a ClickHouse identifier with backticks.
/// Schema-qualified names ("nids.flows") are quoted part-by-part.
fn quote_ident(s: &str) -> String {
    if s.contains('.') {
        let mut parts = s.splitn(2, '.');
        let schema = parts.next().unwrap_or("").replace('`', "``");
        let table  = parts.next().unwrap_or("").replace('`', "``");
        return format!("`{schema}`.`{table}`");
    }
    format!("`{}`", s.replace('`', "``"))
}

fn quote_value(v: &FilterValue) -> String {
    match v {
        FilterValue::Str(s)  => format!("'{}'", s.replace('\'', "\\'")),
        FilterValue::Num(n)  => format!("{n}"),
        FilterValue::Bool(b) => if *b { "1".into() } else { "0".into() },
        FilterValue::Null    => "NULL".into(),
        FilterValue::List(items) => items.iter().map(quote_value).collect::<Vec<_>>().join(", "),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::*;

    fn simple(dims: &[&str], metrics: &[(&str, &str, &str)],
              filters: &[(&str, FilterOp, FilterValue)],
              order: &[(&str, SortDir)], limit: Option<usize>) -> TrafficRequest {
        TrafficRequest {
            collection: "nids.security_events".into(),
            dimensions: dims.iter().map(|s| s.to_string()).collect(),
            metrics: metrics.iter().map(|(a, f, alias)| Metric {
                agg: match *a {
                    "count" => Aggregation::Count, "sum" => Aggregation::Sum,
                    _ => Aggregation::Count,
                },
                field: f.to_string(), alias: alias.to_string(),
            }).collect(),
            filters: filters.iter().map(|(field, op, val)| Filter {
                field: field.to_string(), op: op.clone(), value: val.clone(),
            }).collect(),
            order_by: order.iter().map(|(f, d)| OrderBy {
                field: f.to_string(),
                dir: match d { SortDir::Desc => SortDir::Desc, _ => SortDir::Asc },
            }).collect(),
            limit,
            union_all: vec![],
            joins:     vec![],
        }
    }

    // ── basic ────────────────────────────────────────────────────────────

    #[test]
    fn basic_count() {
        let r   = simple(&["src_ip"], &[("count", "*", "hits")],
                         &[("label", FilterOp::Eq, FilterValue::Str("DoS".into()))],
                         &[("hits", SortDir::Desc)], Some(50));
        let sql = compile_request(&r, 50);
        assert!(sql.contains("COUNT(*) AS `hits`"),     "{sql}");
        assert!(sql.contains("GROUP BY `src_ip`"),      "{sql}");
        assert!(sql.contains("WHERE `label` = 'DoS'"),  "{sql}");
        assert!(sql.contains("ORDER BY `hits` DESC"),   "{sql}");
        assert!(sql.contains("LIMIT 50"),               "{sql}");
    }

    #[test]
    fn select_star_when_no_dims_no_metrics() {
        let r = simple(&[], &[], &[], &[], None);
        assert!(compile_request(&r, 10).starts_with("SELECT * FROM"), "expected SELECT *");
    }

    // ── LIKE / ILIKE ──────────────────────────────────────────────────────

    #[test]
    fn like_pattern() {
        let r   = simple(&["src_ip"], &[],
                         &[("app", FilterOp::Like, FilterValue::Str("HTTP%".into()))],
                         &[], None);
        let sql = compile_request(&r, 10);
        assert!(sql.contains("LIKE 'HTTP%'"), "{sql}");
    }

    #[test]
    fn ilike_pattern() {
        let r   = simple(&["src_ip"], &[],
                         &[("app", FilterOp::ILike, FilterValue::Str("%dns%".into()))],
                         &[], None);
        let sql = compile_request(&r, 10);
        assert!(sql.contains("ILIKE '%dns%'"), "{sql}");
    }

    // ── UNION ALL ────────────────────────────────────────────────────────

    #[test]
    fn union_all() {
        let mut r = simple(&["src_ip"], &[("count", "*", "hits")],
                           &[("label", FilterOp::Eq, FilterValue::Str("DoS".into()))],
                           &[("hits", SortDir::Desc)], Some(100));
        r.union_all = vec![UnionClause {
            collection: None,
            dimensions: vec!["src_ip".into()],
            metrics:    vec![Metric { agg: Aggregation::Count, field: "*".into(), alias: "hits".into() }],
            filters:    vec![Filter { field: "label".into(), op: FilterOp::Eq, value: FilterValue::Str("DDoS".into()) }],
        }];
        let sql = compile_request(&r, 1000);
        assert!(sql.contains("UNION ALL"),              "{sql}");
        assert!(sql.starts_with("SELECT * FROM ("),     "{sql}");
        assert!(sql.contains("ORDER BY `hits` DESC"),   "{sql}");
        assert!(sql.contains("LIMIT 100"),              "{sql}");
    }

    // ── JOIN ─────────────────────────────────────────────────────────────

    #[test]
    fn inner_join() {
        use crate::query::{Join, JoinCondition, JoinKind};
        let mut r = simple(&["src_ip", "label"], &[("count", "*", "hits")],
                           &[], &[("hits", SortDir::Desc)], None);
        r.joins = vec![Join {
            collection: "nids.classified_flows".into(),
            alias:      Some("cf".into()),
            kind:       JoinKind::Inner,
            on:         vec![JoinCondition { left: "flow_id".into(), right: "flow_id".into() }],
            filters:    vec![],
        }];
        let sql = compile_request(&r, 100);
        assert!(sql.contains("INNER JOIN nids.classified_flows AS `cf` ON `flow_id` = `cf`.`flow_id`"), "{sql}");
    }

    #[test]
    fn left_join_with_filter() {
        use crate::query::{Join, JoinCondition, JoinKind};
        let mut r = simple(&["src_ip"], &[], &[], &[], None);
        r.joins = vec![Join {
            collection: "nids.security_events".into(),
            alias:      None,
            kind:       JoinKind::Left,
            on:         vec![JoinCondition { left: "src_ip".into(), right: "src_ip".into() }],
            filters:    vec![Filter { field: "label".into(), op: FilterOp::Eq, value: FilterValue::Str("DoS".into()) }],
        }];
        let sql = compile_request(&r, 100);
        assert!(sql.contains("LEFT JOIN"), "{sql}");
        assert!(sql.contains("'DoS'"), "{sql}");
    }

    // ── translator interface ──────────────────────────────────────────────

    #[test]
    fn translator_compile_roundtrip() {
        let t   = ClickHouseTranslator;
        let r   = simple(&["src_ip"], &[("count", "*", "c")], &[], &[], Some(5));
        let sql = t.compile(&r, 5).unwrap();
        assert!(sql.contains("COUNT(*)"), "{sql}");
    }

    // ── validation ───────────────────────────────────────────────────────

    #[test]
    fn rejects_injection_in_dim() {
        let r = simple(&["src_ip; DROP TABLE x --"], &[], &[], &[], None);
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn quote_escapes_apostrophe() {
        assert_eq!(quote_value(&FilterValue::Str("it's".into())), "'it\\'s'");
    }
}
