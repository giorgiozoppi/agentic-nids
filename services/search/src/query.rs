// Database-agnostic OLAP query DSL.
//
// This module contains only the *what* — the structured query model that callers
// send in JSON.  The *how* (SQL dialect, wire format, connection protocol) lives
// in the concrete translator modules (clickhouse.rs, …).
//
// Adding support for a new database means implementing QueryTranslator and
// StorageBackend for it; the DSL types, the SearchRouter, and all callers stay
// unchanged.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// POST /search/traffic body — database-agnostic OLAP query.
#[derive(Deserialize, Clone)]
pub struct TrafficRequest {
    /// Logical collection name (table / index), e.g. "nids.security_events".
    /// Validated against the Consul allowlist before execution.
    pub collection: String,

    /// Columns to SELECT and GROUP BY (facts / dimensions).
    #[serde(default)]
    pub dimensions: Vec<String>,

    /// Aggregation metrics to compute.
    #[serde(default)]
    pub metrics: Vec<Metric>,

    /// WHERE conditions (AND-combined).
    #[serde(default)]
    pub filters: Vec<Filter>,

    /// Additional sub-queries combined with UNION ALL.
    /// ORDER BY and LIMIT apply to the combined result set.
    #[serde(default)]
    pub union_all: Vec<UnionClause>,

    /// Joins to other OLAP cubes (other Consul-allowed collections).
    /// Each join adds a JOIN clause referencing another table.
    #[serde(default)]
    pub joins: Vec<Join>,

    /// ORDER BY clauses (applied after UNION ALL / JOIN when present).
    #[serde(default)]
    pub order_by: Vec<OrderBy>,

    /// Row limit; capped server-side by the backend's `row_limit` setting.
    pub limit: Option<usize>,
}

/// A JOIN to another OLAP cube (another Consul-allowed collection).
///
/// ```json
/// {
///   "collection": "nids.security_events",
///   "dimensions": ["src_ip"],
///   "joins": [{
///     "collection": "nids.classified_flows",
///     "kind": "inner",
///     "alias": "cf",
///     "on": [{"left": "src_ip", "right": "src_ip"}]
///   }]
/// }
/// ```
#[derive(Deserialize, Clone)]
pub struct Join {
    /// The right-hand table (must be in the Consul allowlist).
    pub collection: String,
    /// Table alias used to qualify columns (default: last segment of collection name).
    pub alias:      Option<String>,
    /// Join type.
    #[serde(default)]
    pub kind:       JoinKind,
    /// Equi-join conditions.  `left` is a column from the outer cube;
    /// `right` is a column from this join's `collection`.
    pub on:         Vec<JoinCondition>,
    /// Additional WHERE-style filter applied only to this joined table.
    #[serde(default)]
    pub filters:    Vec<Filter>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    #[default]
    Inner,
    Left,
    Right,
    Full,
    Cross,
}

#[derive(Deserialize, Clone)]
pub struct JoinCondition {
    /// Column from the outer (left-hand) cube.
    pub left:  String,
    /// Column from the joined (right-hand) cube.
    pub right: String,
}

/// One branch of a UNION ALL.
#[derive(Deserialize, Clone)]
pub struct UnionClause {
    /// Override the collection for this branch (defaults to outer collection).
    pub collection: Option<String>,
    #[serde(default)]
    pub dimensions: Vec<String>,
    #[serde(default)]
    pub metrics:    Vec<Metric>,
    #[serde(default)]
    pub filters:    Vec<Filter>,
}

#[derive(Deserialize, Clone)]
pub struct Metric {
    pub agg:   Aggregation,
    /// Field to aggregate, or `"*"` for `COUNT(*)`.
    pub field: String,
    /// Column alias in the result set.
    pub alias: String,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Count,
    CountDistinct,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Deserialize, Clone)]
pub struct Filter {
    pub field: String,
    pub op:    FilterOp,
    pub value: FilterValue,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    /// Case-sensitive pattern: `%` = any chars, `_` = one char.
    Like,
    /// Case-insensitive pattern (SQL `ILIKE`).
    ILike,
    IsNull,
    IsNotNull,
}

#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum FilterValue {
    Str(String),
    Num(f64),
    Bool(bool),
    List(Vec<FilterValue>),
    Null,
}

#[derive(Deserialize, Clone)]
pub struct OrderBy {
    pub field: String,
    #[serde(default)]
    pub dir:   SortDir,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

// ---------------------------------------------------------------------------
// Response (database-agnostic)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TrafficResponse {
    pub collection:   String,
    pub columns:      Vec<String>,
    pub rows:         Vec<Value>,
    pub row_count:    usize,
    /// True when the result was capped at the server's row limit.
    pub truncated:    bool,
    /// The query string sent to the backend (dialect-specific, for debugging).
    pub compiled_query: String,
}

// ---------------------------------------------------------------------------
// Translator trait
// ---------------------------------------------------------------------------

/// Translates a [`TrafficRequest`] into the query language of a specific backend
/// and parses its raw response into a [`TrafficResponse`].
///
/// Implementors are responsible for SQL/query dialect, escaping, identifier
/// quoting, and response format parsing.  They must be `Send + Sync` so they
/// can be stored in an `Arc` and shared across worker tasks.
pub trait QueryTranslator: Send + Sync + 'static {
    /// Compile the request into a backend-specific query string.
    ///
    /// `limit` is the effective row limit (already clamped to the configured
    /// maximum by the caller).
    fn compile(&self, req: &TrafficRequest, limit: usize) -> anyhow::Result<String>;

    /// Parse a raw JSON response body returned by the backend into a
    /// [`TrafficResponse`].
    fn parse_response(
        &self,
        raw:        Value,
        row_limit:  usize,
        collection: String,
        compiled:   String,
    ) -> anyhow::Result<TrafficResponse>;
}

// ---------------------------------------------------------------------------
// Identifier validation (shared by all translators)
// ---------------------------------------------------------------------------

/// Reject identifiers that contain characters outside `[a-zA-Z0-9_]`.
/// All translators should call this before quoting identifiers.
pub fn validate_ident(s: &str) -> anyhow::Result<()> {
    if s.is_empty() {
        anyhow::bail!("identifier must not be empty");
    }
    if !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!(
            "identifier {:?} contains invalid characters (only [a-zA-Z0-9_] allowed)", s
        );
    }
    Ok(())
}

pub fn validate_collection(col: &str) -> anyhow::Result<()> {
    for part in col.split('.') {
        validate_ident(part)?;
    }
    Ok(())
}

pub fn validate_request(req: &TrafficRequest) -> anyhow::Result<()> {
    validate_collection(&req.collection)?;
    validate_dims_metrics_filters(&req.dimensions, &req.metrics, &req.filters)?;
    for o in &req.order_by {
        validate_ident(&o.field)?;
    }
    for u in &req.union_all {
        if let Some(ref col) = u.collection {
            validate_collection(col)?;
        }
        validate_dims_metrics_filters(&u.dimensions, &u.metrics, &u.filters)?;
    }
    for j in &req.joins {
        validate_collection(&j.collection)?;
        for cond in &j.on {
            validate_ident(&cond.left)?;
            validate_ident(&cond.right)?;
        }
        validate_dims_metrics_filters(&[], &[], &j.filters)?;
    }
    Ok(())
}

pub fn validate_dims_metrics_filters(
    dims:    &[String],
    metrics: &[Metric],
    filters: &[Filter],
) -> anyhow::Result<()> {
    for d in dims    { validate_ident(d)?; }
    for m in metrics { if m.field != "*" { validate_ident(&m.field)?; } validate_ident(&m.alias)?; }
    for f in filters { validate_ident(&f.field)?; }
    Ok(())
}
