// Run 'make proto' to generate the classifierv1 package before building.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strconv"
	"time"

	"nids/orchestrator/internal/ch"
	"nids/orchestrator/internal/grpcclient"
	"nids/orchestrator/internal/state"

	classifierv1 "nids/orchestrator/gen/classifierv1"
)

// defaultLabels must match the classifier's LABELS slice exactly.
var defaultLabels = []string{
	"BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Malware",
}

// envOr returns the env-var value when set, otherwise the provided default.
// Env vars (set by the k8s ConfigMap) take precedence over compiled-in defaults
// so the binary can be reconfigured without rebuilding.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func main() {
	// ── Configuration ─────────────────────────────────────────────────────────
	// Priority: CLI flag > NIDS_* env var (from ConfigMap/Secret) > default.
	// In production the CronJob injects all values via envFrom + secretKeyRef;
	// CLI flags are useful for local ad-hoc runs (e.g. make run-orchestrator).
	stateDir := flag.String("state-dir",
		envOr("NIDS_STATE_DIR", "/state"),
		"directory for persisted cursor state")
	chAddr := flag.String("ch-addr",
		envOr("NIDS_CH_ADDR", "clickhouse.nids.svc.cluster.local:9000"),
		"ClickHouse address (host:port)")
	chDB := flag.String("ch-db",
		envOr("NIDS_CH_DB", "nids"),
		"ClickHouse database name")
	chUser := flag.String("ch-user",
		envOr("NIDS_CH_USER", "default"),
		"ClickHouse username")
	chPassword := flag.String("ch-password",
		envOr("NIDS_CH_PASSWORD", ""),
		"ClickHouse password (prefer NIDS_CH_PASSWORD env var from a Secret)")
	classifierAddr := flag.String("classifier-addr",
		envOr("NIDS_CLASSIFIER_ADDR", "classifier.nids.svc.cluster.local:50051"),
		"classifier gRPC address")
	batchSize := flag.Int("batch-size",
		envOrInt("NIDS_BATCH_SIZE", 256),
		"flows per gRPC batch call")
	limit := flag.Int("limit",
		envOrInt("NIDS_LIMIT", 1000),
		"maximum flows to classify per run")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("orchestrator starting",
		"ch_addr", *chAddr,
		"ch_db", *chDB,
		"classifier_addr", *classifierAddr,
		"limit", *limit,
		"batch_size", *batchSize,
	)

	// ── 1. Load persisted cursor ──────────────────────────────────────────────
	since, err := state.Load(*stateDir)
	if err != nil {
		slog.Error("load state", "error", err)
		os.Exit(1)
	}
	slog.Info("state loaded", "since", since.Format(time.RFC3339))

	// ── 2. Connect to ClickHouse ──────────────────────────────────────────────
	chClient, err := ch.New(*chAddr, *chDB, *chUser, *chPassword)
	if err != nil {
		slog.Error("connect clickhouse", "error", err)
		os.Exit(1)
	}
	defer chClient.Close()

	// ── 3. Connect to classifier gRPC ─────────────────────────────────────────
	grpcClient, err := grpcclient.New(*classifierAddr)
	if err != nil {
		slog.Error("connect classifier", "error", err)
		os.Exit(1)
	}
	defer grpcClient.Close()

	ctx := context.Background()
	startTime := time.Now()

	var (
		totalFlows      int
		totalClassified int
		totalThreats    int
		cursor          = since
	)

	// ── 4. Paginate: fetch → classify → augment → write ───────────────────────
	for totalFlows < *limit {
		remaining := *limit - totalFlows
		fetchN := *batchSize
		if remaining < fetchN {
			fetchN = remaining
		}

		flows, err := chClient.FetchFlows(ctx, cursor, fetchN)
		if err != nil {
			slog.Error("fetch flows", "cursor", cursor, "error", err)
			os.Exit(1)
		}
		if len(flows) == 0 {
			slog.Info("no more flows to process", "total_processed", totalFlows)
			break
		}

		// ── 5. Ask the classifier to augment each flow ────────────────────────
		results, err := grpcClient.ClassifyBatch(ctx, flows)
		if err != nil {
			slog.Error("classify batch", "error", err)
			os.Exit(1)
		}

		aug := augmentFlows(flows, results, defaultLabels)

		// ── 6a. Write all augmented flows (including BENIGN) ──────────────────
		if err := chClient.InsertClassifiedFlows(ctx, aug.ClassifiedFlows); err != nil {
			slog.Error("insert classified flows", "error", err)
			os.Exit(1)
		}

		// ── 6b. Write threat events for alerting ──────────────────────────────
		if err := chClient.InsertSecurityEvents(ctx, aug.SecurityEvents); err != nil {
			slog.Error("insert security events", "error", err)
			os.Exit(1)
		}

		for _, e := range aug.SecurityEvents {
			slog.Info("threat detected",
				"flow_id", e.FlowID,
				"src", e.SrcIP,
				"dst", e.DstIP,
				"attack", e.Label,
				"confidence", e.Confidence,
			)
		}

		totalClassified += len(aug.ClassifiedFlows)
		totalThreats += len(aug.SecurityEvents)

		// ── 7. Advance cursor ─────────────────────────────────────────────────
		maxAt := flows[0].CollectedAt
		for _, f := range flows[1:] {
			if f.CollectedAt.After(maxAt) {
				maxAt = f.CollectedAt
			}
		}
		cursor = maxAt

		if err := state.Save(*stateDir, cursor); err != nil {
			slog.Error("save state", "error", err)
			os.Exit(1)
		}

		totalFlows += len(flows)
		slog.Info("page done",
			"flows_fetched", len(flows),
			"classified", len(aug.ClassifiedFlows),
			"threats", len(aug.SecurityEvents),
			"cursor", cursor.Format(time.RFC3339Nano),
		)

		if len(flows) < fetchN {
			break // last page
		}
	}

	// ── 8. Summary ────────────────────────────────────────────────────────────
	slog.Info("orchestrator run complete",
		"flows_fetched", totalFlows,
		"flows_classified", totalClassified,
		"threats_written", totalThreats,
		"duration", time.Since(startTime).String(),
	)
}

func probabilitiesToJSON(r *classifierv1.ClassifyResponse) string {
	return ch.ProbabilitiesToJSON(defaultLabels, r.Probabilities)
}
