// Consul KV watcher for the search service.
//
// Fetches the list of allowed Milvus collections from Consul KV and keeps it
// fresh via a background polling loop.  Uses arc_swap so readers never block:
// the watcher atomically swaps in the new set while handlers read the old one
// without any locking.
//
// Consul KV key: nids/search/collections
// Expected value: a JSON array of strings, e.g. ["nids_flows","threat_intel"]
//
// If Consul is unavailable at startup the service falls back to the value
// supplied in NIDS_MILVUS_COLLECTIONS.  The background watcher keeps retrying
// so the service self-heals when Consul comes back.

use std::{
    collections::HashSet,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde_json::Value;
use tracing::{info, warn};

pub const CONSUL_KEY: &str = "nids/search/collections";

/// Shared, lock-free view of allowed collections.
pub struct AllowedCollections {
    inner: ArcSwap<HashSet<String>>,
}

impl AllowedCollections {
    pub fn new(initial: HashSet<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::from_pointee(initial),
        })
    }

    /// O(1) lock-free check.
    pub fn is_allowed(&self, collection: &str) -> bool {
        self.inner.load().contains(collection)
    }

    /// Current snapshot (clone). Used only for the /collections endpoint.
    pub fn snapshot(&self) -> HashSet<String> {
        (**self.inner.load()).clone()
    }

    /// Replace the allowlist (called by the watcher task).
    pub fn update(&self, set: HashSet<String>) {
        self.inner.store(Arc::new(set));
    }
}

// ---------------------------------------------------------------------------
// Background watcher
// ---------------------------------------------------------------------------

/// Spawns a Tokio task that polls `consul_url` every `interval` and refreshes
/// `allowed` when the KV value changes.  The task runs for the lifetime of the
/// process; it never panics on network errors.
pub fn spawn_watcher(
    allowed:     Arc<AllowedCollections>,
    consul_url:  String,
    interval:    Duration,
) {
    tokio::spawn(async move {
        let client = Client::new();
        let url    = format!("{}/v1/kv/{}?raw", consul_url.trim_end_matches('/'), CONSUL_KEY);
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            match fetch_collections(&client, &url).await {
                Ok(cols) => {
                    info!(count = cols.len(), "consul: collections refreshed");
                    allowed.update(cols);
                }
                Err(e) => {
                    warn!(error = %e, "consul: failed to refresh collections (retaining current allowlist)");
                }
            }
        }
    });
}

async fn fetch_collections(client: &Client, url: &str) -> anyhow::Result<HashSet<String>> {
    let resp = client.get(url).send().await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Key does not exist yet — treat as empty, not an error.
        return Ok(HashSet::new());
    }

    anyhow::ensure!(resp.status().is_success(), "Consul returned {}", resp.status());

    let body: Value = resp.json().await?;
    let arr = body
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected JSON array from Consul, got {body}"))?;

    let set = arr
        .iter()
        .filter_map(|v| v.as_str())
        .map(str::to_string)
        .collect();

    Ok(set)
}
