// NIDS Search microservice
//
// Unified search gateway for all AI components (ambient agent, chatbot).
// Two endpoints, one internal model:
//
//   POST /search/kb       — ANN vector search (Milvus backend)
//   POST /search/traffic  — OLAP query (ClickHouse backend, OLAP DSL → SQL)
//   GET  /collections     — list allowed collections (from Consul KV)
//   GET  /health          — liveness probe
//
// Both endpoints share the SearchBackend trait and are dispatched through a
// SearchRouter that validates collections against the Consul allowlist.
// Each backend runs a CSP actor pool: workers own their HTTP connections
// exclusively; no mutexes on the hot path.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::Serialize;
use serde_json::Value;
use tracing::info;

mod backend;
mod clickhouse;
mod consul;
mod milvus;
mod pool;
mod query;

use backend::SearchRouter;
use clickhouse::{ChConfig, ClickHouseBackend, ClickHouseTranslator};
use milvus::MilvusBackend;

// ---------------------------------------------------------------------------
// CLI / env configuration
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(version, about = "NIDS unified search gateway")]
struct Args {
    #[arg(long, env = "NIDS_SEARCH_ADDR", default_value = "0.0.0.0:8080")]
    addr: String,

    // ── ClickHouse ────────────────────────────────────────────────────────
    #[arg(long, env = "NIDS_CH_URL",      default_value = "http://localhost:8123")]
    ch_url: String,
    #[arg(long, env = "NIDS_CH_DB",       default_value = "nids")]
    ch_db: String,
    #[arg(long, env = "NIDS_CH_USER",     default_value = "default")]
    ch_user: String,
    #[arg(long, env = "NIDS_CH_PASSWORD", default_value = "")]
    ch_password: String,
    #[arg(long, env = "NIDS_SQL_ROW_LIMIT", default_value_t = 1000)]
    sql_row_limit: usize,
    #[arg(long, env = "NIDS_CH_WORKERS", default_value_t = 4)]
    ch_workers: usize,

    // ── Milvus ────────────────────────────────────────────────────────────
    #[arg(long, env = "NIDS_MILVUS_URI", default_value = "http://localhost:19530")]
    milvus_uri: String,
    #[arg(long, env = "NIDS_VECTOR_TOP_K_LIMIT", default_value_t = 100)]
    vector_top_k_limit: usize,
    #[arg(long, env = "NIDS_MIL_WORKERS", default_value_t = 4)]
    mil_workers: usize,

    // ── Consul ────────────────────────────────────────────────────────────
    /// Consul agent HTTP URL
    #[arg(long, env = "NIDS_CONSUL_URL", default_value = "http://localhost:8500")]
    consul_url: String,

    /// How often (seconds) to re-read the collection allowlist from Consul
    #[arg(long, env = "NIDS_CONSUL_POLL_S", default_value_t = 30)]
    consul_poll_s: u64,

    /// Fallback comma-separated allowlist used when Consul is unreachable
    #[arg(
        long,
        env = "NIDS_MILVUS_COLLECTIONS",
        default_value = "nids_flows",
        value_delimiter = ','
    )]
    fallback_collections: Vec<String>,
}

// ---------------------------------------------------------------------------
// Shared state (immutable after startup)
// ---------------------------------------------------------------------------

struct AppState {
    router: SearchRouter,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> &'static str { "ok" }

#[derive(Serialize)]
struct CollectionsResponse { collections: Vec<String> }

async fn list_collections(State(s): State<Arc<AppState>>) -> Json<CollectionsResponse> {
    Json(CollectionsResponse {
        collections: s.router.allowed_collections(),
    })
}

async fn kb_search(
    State(s): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    dispatch(s, "kb", body).await
}

async fn traffic_search(
    State(s): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    dispatch(s, "traffic", body).await
}

async fn dispatch(
    state: Arc<AppState>,
    path:  &'static str,
    body:  Value,
) -> impl IntoResponse {
    match state.router.dispatch(path, body).await {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e)  => {
            let code = if e.to_string().contains("not in the Consul allowlist") {
                StatusCode::FORBIDDEN
            } else if e.to_string().contains("unknown backend") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            };
            (code, e.to_string()).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let args = Args::parse();

    // ── 1. Seed collection allowlist from Consul (or fallback) ─────────────
    let initial: std::collections::HashSet<String> =
        args.fallback_collections.iter().cloned().collect();
    let allowed = consul::AllowedCollections::new(initial);

    // Background watcher keeps the allowlist fresh.
    consul::spawn_watcher(
        Arc::clone(&allowed),
        args.consul_url.clone(),
        std::time::Duration::from_secs(args.consul_poll_s),
    );
    info!(consul_url = %args.consul_url, poll_s = args.consul_poll_s, "consul watcher started");

    // ── 2. Spawn backend actor pools ────────────────────────────────────────
    let ch = ClickHouseBackend::new(
        ChConfig {
            base_url: args.ch_url.clone(),
            database: args.ch_db.clone(),
            user:     args.ch_user.clone(),
            password: args.ch_password.clone(),
        },
        args.ch_workers,
        args.sql_row_limit,
        // Swap ClickHouseTranslator for another QueryTranslator impl to target
        // a different database without touching any other code.
        Arc::new(ClickHouseTranslator),
    );
    info!(workers = args.ch_workers, url = %args.ch_url, "clickhouse pool ready");

    let mil = MilvusBackend::new(
        args.milvus_uri.clone(),
        args.mil_workers,
        args.vector_top_k_limit,
    ).await?;
    info!(workers = args.mil_workers, uri = %args.milvus_uri, "milvus pool ready");

    // ── 3. Register backends in the unified router ──────────────────────────
    let mut router = SearchRouter::new(Arc::clone(&allowed));
    router.register("traffic", ch);
    router.register("kb",      mil);

    let state = Arc::new(AppState { router });

    // ── 4. Start HTTP server ────────────────────────────────────────────────
    let app = Router::new()
        .route("/health",          get(health))
        .route("/collections",     get(list_collections))
        .route("/search/kb",       post(kb_search))
        .route("/search/traffic",  post(traffic_search))
        .with_state(Arc::clone(&state))
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&args.addr).await?;
    info!(addr = %listener.local_addr()?, "nids-search listening");
    axum::serve(listener, app).await?;
    Ok(())
}
