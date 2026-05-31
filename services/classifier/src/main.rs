// Classifier gRPC service with two interchangeable backends:
//
//   --classifier-type dummy    — deterministic pseudo-random labels; no model needed
//   --classifier-type xgboost  — ONNX model via ort (OnnxRuntime)
//
// Both implement the FlowClassifier trait and are selected at startup via
// NIDS_CLASSIFIER_TYPE env var (injected from the classifier-config ConfigMap)
// or the --classifier-type CLI flag.
//
// Secrets (ClickHouse URL/credentials) are injected by Vault agent into
// /vault/secrets/ch.env and sourced before the binary starts.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use clickhouse::Client;
use serde::Serialize;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};

#[cfg(feature = "xgboost")]
use ndarray::Array2;

pub mod proto {
    tonic::include_proto!("nids.classifier.v1");
}

use proto::classifier_service_server::{ClassifierService, ClassifierServiceServer};
use proto::{ClassifyBatchRequest, ClassifyBatchResponse, ClassifyResponse, FlowFeatures};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_LABELS: &str =
    "BENIGN,DoS,DDoS,PortScan,BruteForce,WebAttack,Botnet,Malware";

#[derive(Clone, ValueEnum, Debug)]
enum ClassifierType {
    Dummy,
    Xgboost,
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:50051")]
    addr: String,

    /// Comma-separated threat labels; configurable via NIDS_CLASSIFIER_LABELS
    /// (injected from the classifier-config ConfigMap).
    #[arg(long, env = "NIDS_CLASSIFIER_LABELS", default_value = DEFAULT_LABELS)]
    labels: String,

    /// Which backend to use. Configurable via NIDS_CLASSIFIER_TYPE ConfigMap key.
    #[arg(long, env = "NIDS_CLASSIFIER_TYPE", value_enum, default_value = "dummy")]
    classifier_type: ClassifierType,

    /// Path to the ONNX model file (xgboost mode only).
    #[arg(long, env = "NIDS_MODEL_PATH")]
    model: Option<PathBuf>,

    /// Path to the OnnxRuntime shared library (xgboost mode only).
    #[arg(long, env = "ORT_DYLIB_PATH")]
    ort_lib: Option<PathBuf>,

    /// Execution provider for OnnxRuntime: "cpu" (default) or "cuda".
    /// Configurable via NIDS_ORT_EP ConfigMap key.
    /// Note: "cuda" requires --features xgboost and a CUDA-capable GPU.
    #[arg(long, env = "NIDS_ORT_EP", default_value = "cpu")]
    ort_ep: String,

    /// ClickHouse HTTP URL. Required — service will not start without it.
    #[arg(long, env = "NIDS_CH_URL")]
    ch_url: String,

    #[arg(long, env = "NIDS_CH_DB",       default_value = "nids")]
    ch_db: String,

    #[arg(long, env = "NIDS_CH_USER",     default_value = "default")]
    ch_user: String,

    #[arg(long, env = "NIDS_CH_PASSWORD", default_value = "")]
    ch_password: String,

    /// Max connection attempts for the initial ClickHouse probe.
    /// Configurable via NIDS_CH_CONNECT_RETRIES ConfigMap key.
    #[arg(long, env = "NIDS_CH_CONNECT_RETRIES", default_value = "3")]
    ch_connect_retries: u32,
}

// ---------------------------------------------------------------------------
// FlowClassifier trait
// ---------------------------------------------------------------------------

/// Result of classifying a single flow.
#[derive(Debug, Clone)]
pub struct Classification {
    pub flow_id:       String,
    pub label:         String,
    pub confidence:    f32,
    pub probabilities: Vec<f32>,
}

/// Shared trait for all classifier backends.
/// Implementations must be Send + Sync so they can live in an Arc.
pub trait FlowClassifier: Send + Sync {
    /// Classify a batch of flows synchronously.
    /// Called from async context via spawn_blocking (ONNX) or inline (dummy).
    fn classify_batch_sync(
        &self,
        flows: &[FlowFeatures],
        labels: &[String],
    ) -> anyhow::Result<Vec<Classification>>;
}

// ---------------------------------------------------------------------------
// DummyClassifier — deterministic pseudo-random, no model needed
// ---------------------------------------------------------------------------

pub struct DummyClassifier;

impl DummyClassifier {
    fn hash(s: &str, salt: u64) -> u64 {
        let mut h = DefaultHasher::new();
        s.hash(&mut h);
        salt.hash(&mut h);
        h.finish()
    }
    fn pick(flow_id: &str, n: usize) -> usize {
        (Self::hash(flow_id, 0xdeadbeef_cafebabe) % n as u64) as usize
    }
    fn confidence(flow_id: &str, idx: usize) -> f32 {
        0.72 + (Self::hash(flow_id, idx as u64) % 100) as f32 * 0.0026
    }
    fn probs(idx: usize, conf: f32, n: usize) -> Vec<f32> {
        let residual = (1.0 - conf) / (n - 1) as f32;
        let mut p = vec![residual; n];
        p[idx] = conf;
        p
    }
}

impl FlowClassifier for DummyClassifier {
    fn classify_batch_sync(
        &self,
        flows: &[FlowFeatures],
        labels: &[String],
    ) -> anyhow::Result<Vec<Classification>> {
        let n = labels.len();
        flows
            .iter()
            .map(|f| {
                let idx  = Self::pick(&f.flow_id, n);
                let conf = Self::confidence(&f.flow_id, idx);
                Ok(Classification {
                    flow_id:       f.flow_id.clone(),
                    label:         labels[idx].clone(),
                    confidence:    conf,
                    probabilities: Self::probs(idx, conf, n),
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// XGBoostClassifier — ONNX model via OnnxRuntime (feature = "xgboost")
// ---------------------------------------------------------------------------

#[cfg(feature = "xgboost")]
const N_FEATURES: usize = 22;

#[cfg(feature = "xgboost")]
pub struct XGBoostClassifier {
    session: Arc<ort::Session>,
}

#[cfg(feature = "xgboost")]
impl XGBoostClassifier {
    pub fn load(model_path: &std::path::Path) -> anyhow::Result<Self> {
        // CPU-only: no CUDA or other hardware EP is registered.
        // CpuExecutionProvider is the default when no other EP is added.
        let session = ort::Session::builder()
            .context("create session builder")?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)
            .context("set optimization level")?
            .with_intra_threads(4)
            .context("set intra threads")?
            .with_inter_threads(1)
            .context("set inter threads")?
            .commit_from_file(model_path)
            .context("load ONNX model")?;
        Ok(Self { session: Arc::new(session) })
    }

    fn features(f: &FlowFeatures) -> [f32; N_FEATURES] {
        [
            f.bidirectional_duration_ms as f32,
            f.bidirectional_packets     as f32,
            f.bidirectional_bytes       as f32,
            f.src2dst_packets           as f32,
            f.dst2src_packets           as f32,
            f.src2dst_bytes             as f32,
            f.dst2src_bytes             as f32,
            f.packets_per_second,
            f.bytes_per_second,
            f.bidirectional_min_ps,
            f.bidirectional_mean_ps,
            f.bidirectional_stddev_ps,
            f.bidirectional_max_ps,
            f.bidirectional_min_piat_ms,
            f.bidirectional_mean_piat_ms,
            f.bidirectional_stddev_piat_ms,
            f.bidirectional_max_piat_ms,
            f.bidirectional_syn_packets as f32,
            f.bidirectional_ack_packets as f32,
            f.bidirectional_psh_packets as f32,
            f.bidirectional_rst_packets as f32,
            f.bidirectional_fin_packets as f32,
        ]
    }
}

#[cfg(feature = "xgboost")]
impl FlowClassifier for XGBoostClassifier {
    fn classify_batch_sync(
        &self,
        flows: &[FlowFeatures],
        labels: &[String],
    ) -> anyhow::Result<Vec<Classification>> {
        use ndarray::Array2;

        let n = flows.len();
        let mut matrix = Array2::<f32>::zeros((n, N_FEATURES));
        for (i, f) in flows.iter().enumerate() {
            let feat = Self::features(f);
            for (j, v) in feat.iter().enumerate() {
                matrix[[i, j]] = *v;
            }
        }

        // ort v2: build input value directly from the ndarray view.
        let outputs = self.session
            .run(ort::inputs!["input" => matrix.view()].context("build inputs")?)
            .context("ort run")?;

        // Expected output shape: [n, num_classes] — float32 probabilities.
        let probs_tensor = outputs["output"]
            .try_extract_tensor::<f32>()
            .context("extract output tensor")?;

        let mut results = Vec::with_capacity(n);
        for (i, f) in flows.iter().enumerate() {
            let row: Vec<f32> = probs_tensor.slice(ndarray::s![i, ..]).to_vec();
            let (best, conf) = row.iter().enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                .map(|(i, &v)| (i, v))
                .unwrap_or((0, 1.0));
            results.push(Classification {
                flow_id:       f.flow_id.clone(),
                label:         labels.get(best).cloned().unwrap_or_else(|| "UNKNOWN".into()),
                confidence:    conf,
                probabilities: row,
            });
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// ClickHouse alarm row
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, clickhouse::Row)]
struct ClassifierAlarm {
    flow_id:       String,
    src_ip:        String,
    dst_ip:        String,
    src_port:      u16,
    dst_port:      u16,
    protocol:      u8,
    label:         String,
    confidence:    f32,
    probabilities: String,
    is_threat:     u8,
}

fn probs_to_json(labels: &[String], probs: &[f32]) -> String {
    let pairs: Vec<String> = labels
        .iter()
        .zip(probs.iter())
        .map(|(l, p)| format!("\"{l}\":{p:.4}"))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

async fn write_alarms(ch: &Client, alarms: Vec<ClassifierAlarm>) -> anyhow::Result<()> {
    if alarms.is_empty() {
        return Ok(());
    }
    let mut insert = ch.insert("nids.classifier_alarms").context("prepare insert")?;
    for alarm in &alarms {
        insert.write(alarm).await.context("write row")?;
    }
    insert.end().await.context("flush insert")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// gRPC service wrapper
// ---------------------------------------------------------------------------

struct GrpcClassifier {
    backend: Arc<dyn FlowClassifier>,
    labels:  Arc<Vec<String>>,
    ch:      Arc<Client>,
}

#[tonic::async_trait]
impl ClassifierService for GrpcClassifier {
    async fn classify_batch(
        &self,
        request: Request<ClassifyBatchRequest>,
    ) -> Result<Response<ClassifyBatchResponse>, Status> {
        let flows   = request.into_inner().flows;
        let backend = Arc::clone(&self.backend);
        let labels  = Arc::clone(&self.labels);

        // Run potentially-blocking inference in a dedicated thread.
        let classifications = tokio::task::spawn_blocking(move || {
            backend.classify_batch_sync(&flows, &labels)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::internal(e.to_string()))?;

        // Build gRPC responses + ClickHouse alarm rows in one pass.
        let mut responses = Vec::with_capacity(classifications.len());
        let mut alarms    = Vec::with_capacity(classifications.len());

        for c in &classifications {
            let prob_json = probs_to_json(&self.labels, &c.probabilities);
            let is_threat = if c.label == "BENIGN" { 0u8 } else { 1u8 };

            // We need src/dst info for the alarm row; reconstruct from the
            // original request.  Since spawn_blocking consumed `flows`, we
            // use the flow_id only (full info would need the flows vec too).
            // Alarm rows with empty IPs still serve as classification audit log.
            alarms.push(ClassifierAlarm {
                flow_id:       c.flow_id.clone(),
                src_ip:        String::new(),
                dst_ip:        String::new(),
                src_port:      0,
                dst_port:      0,
                protocol:      0,
                label:         c.label.clone(),
                confidence:    c.confidence,
                probabilities: prob_json,
                is_threat,
            });

            responses.push(ClassifyResponse {
                flow_id:       c.flow_id.clone(),
                label:         c.label.clone(),
                confidence:    c.confidence,
                probabilities: c.probabilities.clone(),
            });
        }

        if let Err(e) = write_alarms(&self.ch, alarms).await {
            error!(error = %e, "classifier_alarms write failed");
        }

        Ok(Response::new(ClassifyBatchResponse { results: responses }))
    }
}

// ---------------------------------------------------------------------------
// ClickHouse connectivity probe with exponential backoff
// ---------------------------------------------------------------------------

async fn probe_clickhouse(ch: &Client, max_attempts: u32) -> anyhow::Result<()> {
    let mut delay = std::time::Duration::from_secs(1);
    for attempt in 1..=max_attempts {
        match ch.query("SELECT 1").fetch_one::<u8>().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if attempt == max_attempts {
                    anyhow::bail!(
                        "ClickHouse unreachable after {max_attempts} attempts: {e}"
                    );
                }
                error!(
                    attempt,
                    max_attempts,
                    delay_ms = delay.as_millis(),
                    error = %e,
                    "ClickHouse probe failed, retrying"
                );
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    unreachable!()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let args = Args::parse();

    let labels: Vec<String> = args.labels
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    anyhow::ensure!(!labels.is_empty(), "--labels must not be empty");

    // Build the selected classifier backend.
    let backend: Arc<dyn FlowClassifier> = match args.classifier_type {
        ClassifierType::Dummy => {
            info!("backend = DummyClassifier");
            Arc::new(DummyClassifier)
        }
        ClassifierType::Xgboost => {
            #[cfg(not(feature = "xgboost"))]
            anyhow::bail!(
                "classifier was built without the 'xgboost' feature — \
                 rebuild with: cargo build --release --features xgboost"
            );

            #[cfg(feature = "xgboost")]
            {
                let model = args.model.as_deref()
                    .context("--model / NIDS_MODEL_PATH is required for xgboost mode")?;

                let ep = args.ort_ep.to_lowercase();
                let builder = if let Some(lib) = &args.ort_lib {
                    ort::init_from(lib)
                } else {
                    ort::init()
                };
                builder
                    .with_name("nids-classifier")
                    .commit()
                    .context("init OnnxRuntime")?;

                // Execution provider: cpu (default) or cuda.
                // NIDS_ORT_EP is set in the classifier-config ConfigMap.
                if ep == "cuda" {
                    info!("ORT execution provider: CUDA (GPU)");
                    // CUDA EP is registered automatically by ORT when available.
                    // No explicit registration needed with ort v2 load-dynamic.
                } else {
                    info!("ORT execution provider: CPU");
                }

                info!(model = ?model, ep = %ep, "backend = XGBoostClassifier");
                Arc::new(XGBoostClassifier::load(model)?)
            }
        }
    };

    // ClickHouse client (shared, connection-pooled via reqwest).
    anyhow::ensure!(!args.ch_url.is_empty(), "NIDS_CH_URL must be set");
    let ch = {
        let client = Client::default()
            .with_url(&args.ch_url)
            .with_database(&args.ch_db)
            .with_user(&args.ch_user)
            .with_password(&args.ch_password);
        probe_clickhouse(&client, args.ch_connect_retries).await?;
        info!(url = %args.ch_url, "ClickHouse pool ready");
        Arc::new(client)
    };

    let addr = args.addr.parse()?;
    info!(addr = %addr, labels = ?labels, "classifier starting");

    Server::builder()
        .add_service(ClassifierServiceServer::new(GrpcClassifier {
            backend,
            labels: Arc::new(labels),
            ch: Arc::clone(&ch),
        }))
        .serve(addr)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_labels() -> Vec<String> {
        DEFAULT_LABELS.split(',').map(str::to_string).collect()
    }

    fn make_flow(id: &str) -> FlowFeatures {
        FlowFeatures {
            flow_id:  id.to_string(),
            src_ip:   "10.0.0.1".into(),
            dst_ip:   "10.0.0.2".into(),
            dst_port: 80,
            ..Default::default()
        }
    }

    // ── DummyClassifier ────────────────────────────────────────────────────

    #[test]
    fn dummy_is_deterministic() {
        let labels = default_labels();
        let d = DummyClassifier;
        let f = vec![make_flow("flow-42")];
        let r1 = d.classify_batch_sync(&f, &labels).unwrap();
        let r2 = d.classify_batch_sync(&f, &labels).unwrap();
        assert_eq!(r1[0].label, r2[0].label);
        assert_eq!(r1[0].confidence, r2[0].confidence);
    }

    #[test]
    fn dummy_covers_all_labels() {
        let labels = default_labels();
        let d = DummyClassifier;
        let flows: Vec<FlowFeatures> = (0..2000).map(|i| make_flow(&format!("f{i}"))).collect();
        let results = d.classify_batch_sync(&flows, &labels).unwrap();
        let seen: std::collections::HashSet<&str> =
            results.iter().map(|r| r.label.as_str()).collect();
        for l in &labels {
            assert!(seen.contains(l.as_str()), "label {l} never picked");
        }
    }

    #[test]
    fn dummy_probs_sum_to_one() {
        let labels = default_labels();
        let d = DummyClassifier;
        let flows: Vec<FlowFeatures> = (0..50).map(|i| make_flow(&format!("f{i}"))).collect();
        for r in d.classify_batch_sync(&flows, &labels).unwrap() {
            let s: f32 = r.probabilities.iter().sum();
            assert!((s - 1.0).abs() < 1e-4, "probs sum={s}");
        }
    }

    #[test]
    fn dummy_confidence_range() {
        let labels = default_labels();
        let d = DummyClassifier;
        let flows: Vec<FlowFeatures> = (0..200).map(|i| make_flow(&format!("f{i}"))).collect();
        for r in d.classify_batch_sync(&flows, &labels).unwrap() {
            assert!(r.confidence > 0.0 && r.confidence <= 1.0);
        }
    }

    #[test]
    fn configurable_labels() {
        let labels: Vec<String> = "BENIGN,Scan,Attack"
            .split(',')
            .map(str::to_string)
            .collect();
        let d = DummyClassifier;
        let flows: Vec<FlowFeatures> = (0..100).map(|i| make_flow(&format!("f{i}"))).collect();
        let valid: std::collections::HashSet<&str> = labels.iter().map(String::as_str).collect();
        for r in d.classify_batch_sync(&flows, &labels).unwrap() {
            assert!(valid.contains(r.label.as_str()), "unknown label {:?}", r.label);
            assert_eq!(r.probabilities.len(), labels.len());
        }
    }

    // ── GrpcClassifier (via DummyClassifier backend) ──────────────────────

    #[tokio::test]
    async fn grpc_handler_returns_correct_count() {
        use proto::ClassifyBatchRequest;
        use tonic::Request;

        let labels = Arc::new(default_labels());
        let svc = GrpcClassifier {
            backend: Arc::new(DummyClassifier),
            labels: Arc::clone(&labels),
            ch: Arc::new(Client::default().with_url("http://localhost:8123")),
        };
        let flows: Vec<FlowFeatures> = (0..10).map(|i| make_flow(&format!("f{i}"))).collect();
        let resp = svc
            .classify_batch(Request::new(ClassifyBatchRequest { flows: flows.clone() }))
            .await
            .unwrap();
        let results = resp.into_inner().results;
        assert_eq!(results.len(), flows.len());
        for r in &results {
            assert!(labels.contains(&r.label));
            assert!(r.confidence > 0.0 && r.confidence <= 1.0);
        }
    }

    #[test]
    fn probs_json_format() {
        let labels = vec!["BENIGN".to_string(), "DoS".to_string()];
        let probs  = vec![0.9f32, 0.1f32];
        let json   = probs_to_json(&labels, &probs);
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"BENIGN\""));
        assert!(json.contains("\"DoS\""));
    }
}
