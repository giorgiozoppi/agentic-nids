// SearchBackend trait and SearchRouter.
//
// Architecture
// ─────────────
//
//   SearchBackend<Req, Resp>   ← typed trait; each concrete backend implements this
//          │
//          │ register() erases the types into a closure:
//          │   Value → BoxFuture<Value>
//          ▼
//   SearchRouter               ← runtime registry of named, type-erased backends
//          │
//          │ dispatch("kb" | "traffic", Value) → Result<Value>
//          ▼
//   Axum handler               ← calls dispatch; knows nothing about backend types
//
// The concrete backends (ClickHouseBackend, MilvusBackend) use CSP actor pools
// internally, so the trait boundary here is purely logical.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tracing::error;

use crate::consul::AllowedCollections;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A backend that handles search requests of type `Req` and returns `Resp`.
///
/// Implementors use CSP actor pools internally; calling `search` dispatches a
/// command to a free worker and awaits the reply via a oneshot channel.
pub trait SearchBackend: Send + Sync + 'static {
    type Req:  Send + DeserializeOwned + 'static;
    type Resp: Send + Serialize + 'static;

    fn search(
        &self,
        req: Self::Req,
    ) -> impl Future<Output = anyhow::Result<Self::Resp>> + Send;
}

// ---------------------------------------------------------------------------
// Type-erased dispatch function stored in the router
// ---------------------------------------------------------------------------

type BoxFuture = Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send>>;
type DispatchFn = Arc<dyn Fn(Value) -> BoxFuture + Send + Sync>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub struct SearchRouter {
    routes:   HashMap<&'static str, DispatchFn>,
    allowed:  Arc<AllowedCollections>,
}

impl SearchRouter {
    pub fn new(allowed: Arc<AllowedCollections>) -> Self {
        Self {
            routes:  HashMap::new(),
            allowed,
        }
    }

    /// Register a backend under `path` (e.g. `"kb"` or `"traffic"`).
    ///
    /// The backend's concrete `Req`/`Resp` types are erased here: the closure
    /// deserialises the incoming `Value` into `B::Req`, calls `backend.search`,
    /// and serialises the result back to `Value`.
    pub fn register<B: SearchBackend>(&mut self, path: &'static str, backend: Arc<B>) {
        let f: DispatchFn = Arc::new(move |val: Value| {
            let b = Arc::clone(&backend);
            Box::pin(async move {
                let req: B::Req = serde_json::from_value(val)
                    .map_err(|e| anyhow::anyhow!("invalid request: {e}"))?;
                let resp = b.search(req).await?;
                serde_json::to_value(resp).map_err(Into::into)
            })
        });
        self.routes.insert(path, f);
    }

    /// Dispatch a request to the named backend.
    ///
    /// Validates the `collection` field in `params` against the Consul-managed
    /// allowlist before forwarding.  Unknown paths return an error immediately.
    pub async fn dispatch(&self, path: &str, params: Value) -> anyhow::Result<Value> {
        // Collection allowlist check (lock-free read via ArcSwap)
        if let Some(col) = params.get("collection").and_then(|v| v.as_str()) {
            if !self.allowed.is_allowed(col) {
                anyhow::bail!(
                    "collection {:?} is not in the Consul allowlist \
                     (key: nids/search/collections)",
                    col
                );
            }
        }

        let f = self.routes.get(path).ok_or_else(|| {
            anyhow::anyhow!("unknown backend {:?}; registered: {:?}", path,
                self.routes.keys().collect::<Vec<_>>())
        })?;

        f(params.clone()).await.map_err(|e| {
            error!(path, error = %e, "backend error");
            e
        })
    }

    /// Return the currently allowed collections (for /collections endpoint).
    pub fn allowed_collections(&self) -> Vec<String> {
        let mut v: Vec<String> = self.allowed.snapshot().into_iter().collect();
        v.sort();
        v
    }
}
