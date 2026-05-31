// Milvus backend.
//
// Implements SearchBackend<Req=KbRequest, Resp=VectorSearchResponse>.
// Uses the Milvus REST API v2 (no gRPC, no proto codegen).
//
// Flow per request:
//   handler → MilvusBackend::search
//           → validate collection (Consul allowlist checked by router before this)
//           → create oneshot (tx, rx)
//           → Pool::dispatch(MilCmd { ... , reply: tx })
//           → await rx
//           ← worker executes REST call, sends result via tx

use std::sync::Arc;

use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::backend::SearchBackend;
use crate::pool::{Pool, CHANNEL_CAP};

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

/// POST /search/kb body
#[derive(Deserialize)]
pub struct KbRequest {
    /// Target Milvus collection (validated against Consul allowlist by the router).
    pub collection:    String,
    /// Query embedding — must match the index dimension of the collection.
    pub embedding:     Vec<f32>,
    /// Number of nearest neighbours (capped server-side at top_k_limit).
    #[serde(default = "default_top_k")]
    pub top_k:         usize,
    /// Optional Milvus boolean filter, e.g. `label == "DoS"`.
    pub filter:        Option<String>,
    /// Scalar fields to return per hit (None → all).
    pub output_fields: Option<Vec<String>>,
}

fn default_top_k() -> usize { 5 }

#[derive(Serialize)]
pub struct VectorSearchResponse {
    pub collection: String,
    pub hits:       Vec<VectorHit>,
}

#[derive(Serialize)]
pub struct VectorHit {
    pub id:       i64,
    pub distance: f32,
    pub fields:   Value,
}

// ---------------------------------------------------------------------------
// Command (sent from handler to worker)
// ---------------------------------------------------------------------------

pub struct MilCmd {
    pub collection:    String,
    pub embedding:     Vec<f32>,
    pub top_k:         usize,
    pub filter:        Option<String>,
    pub output_fields: Option<Vec<String>>,
    pub reply:         oneshot::Sender<anyhow::Result<Vec<VectorHit>>>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

pub struct MilvusBackend {
    pool:         Pool<MilCmd>,
    top_k_limit:  usize,
}

impl MilvusBackend {
    /// Spawn `workers` actor tasks and return a backend ready to dispatch.
    pub async fn new(
        milvus_uri:  String,
        workers:     usize,
        top_k_limit: usize,
    ) -> anyhow::Result<Arc<Self>> {
        // Connectivity check before spawning workers.
        ping(&milvus_uri).await.context("cannot reach Milvus")?;

        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel::<MilCmd>(CHANNEL_CAP);
            tokio::spawn(mil_worker(rx, milvus_uri.clone()));
            senders.push(tx);
        }

        Ok(Arc::new(Self {
            pool: Pool::from_senders(senders),
            top_k_limit,
        }))
    }
}

impl SearchBackend for MilvusBackend {
    type Req  = KbRequest;
    type Resp = VectorSearchResponse;

    async fn search(&self, req: KbRequest) -> anyhow::Result<VectorSearchResponse> {
        let top_k = req.top_k.min(self.top_k_limit);
        let col   = req.collection.clone();

        let (tx, rx) = oneshot::channel();
        self.pool.dispatch(MilCmd {
            collection:    req.collection,
            embedding:     req.embedding,
            top_k,
            filter:        req.filter,
            output_fields: req.output_fields,
            reply:         tx,
        }).await?;

        let hits = rx.await.context("worker dropped reply channel")??;
        Ok(VectorSearchResponse { collection: col, hits })
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

async fn mil_worker(mut rx: mpsc::Receiver<MilCmd>, base_url: String) {
    // Each worker owns its client → its own HTTP connection pool.
    let client = Client::builder()
        .pool_max_idle_per_host(4)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    let search_url = format!(
        "{}/v2/vectordb/entities/search",
        base_url.trim_end_matches('/')
    );

    while let Some(MilCmd { collection, embedding, top_k, filter, output_fields, reply }) = rx.recv().await {
        let result = execute(&client, &search_url, collection, embedding, top_k, filter, output_fields).await;
        let _ = reply.send(result);
    }
}

async fn execute(
    client:       &Client,
    url:          &str,
    collection:   String,
    embedding:    Vec<f32>,
    top_k:        usize,
    filter:       Option<String>,
    output_fields: Option<Vec<String>>,
) -> anyhow::Result<Vec<VectorHit>> {
    let mut body = json!({
        "collectionName": collection,
        "data":           [embedding],
        "limit":          top_k,
        "outputFields":   output_fields.as_deref().unwrap_or(&[]),
    });
    if let Some(f) = filter {
        body["filter"] = Value::String(f);
    }

    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .context("Milvus search request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text   = resp.text().await.unwrap_or_default();
        anyhow::bail!("Milvus {status}: {text}");
    }

    let envelope: MilvusEnvelope = resp.json().await.context("parse Milvus response")?;
    if envelope.code != 0 {
        anyhow::bail!(
            "Milvus error {}: {}",
            envelope.code,
            envelope.message.unwrap_or_default()
        );
    }

    let hits = envelope
        .data
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .map(|h| VectorHit {
            id:       h.id.unwrap_or(0),
            distance: h.distance.unwrap_or(0.0),
            fields:   h.extra.unwrap_or(Value::Null),
        })
        .collect();

    Ok(hits)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn ping(base_url: &str) -> anyhow::Result<()> {
    let url = format!(
        "{}/v2/vectordb/collections/list",
        base_url.trim_end_matches('/')
    );
    let client = Client::new();
    let resp   = client.post(&url).json(&json!({})).send().await?;
    anyhow::ensure!(resp.status().is_success(), "Milvus ping: {}", resp.status());
    Ok(())
}

// Milvus REST v2 response envelope
#[derive(Deserialize)]
struct MilvusEnvelope {
    code:    i64,
    message: Option<String>,
    data:    Option<Vec<Vec<MilvusHit>>>,
}

#[derive(Deserialize)]
struct MilvusHit {
    id:       Option<i64>,
    distance: Option<f32>,
    #[serde(flatten)]
    extra:    Option<Value>,
}
