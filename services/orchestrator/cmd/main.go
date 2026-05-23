// Run 'make proto' to generate the classifierv1 package before building.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"nids/services/orchestrator/internal/ch"
	"nids/services/orchestrator/internal/grpcclient"
	"nids/services/orchestrator/internal/state"

	// Run 'make proto' to generate this package
	classifierv1 "nids/services/gen/classifierv1"
)

func main() {
	stateDir       := flag.String("state-dir",        "/state",                                         "directory for persisted state")
	chAddr         := flag.String("ch-addr",          "clickhouse.nids.svc.cluster.local:9000",         "ClickHouse address (host:port)")
	chDB           := flag.String("ch-db",            "nids",                                           "ClickHouse database name")
	chUser         := flag.String("ch-user",          "default",                                        "ClickHouse username")
	chPassword     := flag.String("ch-password",      "",                                               "ClickHouse password")
	classifierAddr := flag.String("classifier-addr",  "classifier.nids.svc.cluster.local:50051",        "classifier gRPC address")
	batchSize      := flag.Int("batch-size",          256,                                              "flows per gRPC batch call")
	limit          := flag.Int("limit",               10000,                                            "maximum flows to process per run")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// ── 1. Load persisted timestamp ──────────────────────────────────────────
	since, err := state.Load(*stateDir)
	if err != nil {
		slog.Error("load state", "error", err)
		os.Exit(1)
	}
	slog.Info("state loaded", "since", since.Format(time.RFC3339))

	// ── 2. Connect to ClickHouse ─────────────────────────────────────────────
	chClient, err := ch.New(*chAddr, *chDB, *chUser, *chPassword)
	if err != nil {
		slog.Error("connect clickhouse", "error", err)
		os.Exit(1)
	}
	defer chClient.Close()

	// ── 3. Connect to classifier gRPC ────────────────────────────────────────
	grpcClient, err := grpcclient.New(*classifierAddr)
	if err != nil {
		slog.Error("connect classifier", "error", err)
		os.Exit(1)
	}
	defer grpcClient.Close()

	ctx := context.Background()
	startTime := time.Now()

	var (
		totalFlows  int
		totalEvents int
		cursor      = since
	)

	// ── 4. Paginate through flows ────────────────────────────────────────────
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
			slog.Info("no more flows", "total_processed", totalFlows)
			break
		}

		// ── 5. Classify ──────────────────────────────────────────────────────
		results, err := grpcClient.ClassifyBatch(ctx, flows)
		if err != nil {
			slog.Error("classify batch", "error", err)
			os.Exit(1)
		}

		// Build a flow_id → flow map for quick lookup.
		flowByID := make(map[string]ch.Flow, len(flows))
		for _, f := range flows {
			flowByID[f.FlowID] = f
		}

		// Build security events — skip BENIGN flows; store threats immediately
		// upon receipt of the gRPC response.
		events := make([]ch.SecurityEvent, 0, len(results))
		for _, r := range results {
			if r.Label == "BENIGN" {
				continue
			}
			f, ok := flowByID[r.FlowId]
			if !ok {
				continue
			}
			events = append(events, ch.SecurityEvent{
				FlowID:                  f.FlowID,
				SrcIP:                   f.SrcIP,
				DstIP:                   f.DstIP,
				SrcPort:                 f.SrcPort,
				DstPort:                 f.DstPort,
				Protocol:                f.Protocol,
				Label:                   r.Label,
				Confidence:              r.Confidence,
				Probabilities:           probabilitiesToJSON(r),
				BidirectionalPackets:    f.BidirectionalPackets,
				BidirectionalBytes:      f.BidirectionalBytes,
				BidirectionalDurationMs: f.BidirectionalDurationMs,
			})
		}

		// ── 6. Insert threat events immediately after classification ──────────
		if err := chClient.InsertSecurityEvents(ctx, events); err != nil {
			slog.Error("insert security events", "error", err)
			os.Exit(1)
		}
		for _, e := range events {
			slog.Info("security event stored",
				"flow_id", e.FlowID,
				"src_ip", e.SrcIP,
				"dst_ip", e.DstIP,
				"attack", e.Label,
				"confidence", e.Confidence,
			)
		}
		totalEvents += len(events)

		// ── 7. Advance cursor to max collected_at in this page ────────────────
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
		slog.Info("page processed",
			"flows", len(flows),
			"events", len(events),
			"cursor", cursor.Format(time.RFC3339Nano),
		)

		if len(flows) < fetchN {
			// Last page — fewer rows than requested means we reached the end.
			break
		}
	}

	// ── 8. Summary ────────────────────────────────────────────────────────────
	slog.Info("orchestrator run complete",
		"flows_processed", totalFlows,
		"events_written",  totalEvents,
		"duration",        time.Since(startTime).String(),
	)
}

// probabilitiesToJSON renders the probability slice in the response as a JSON
// object using the canonical label order from the classifier defaults.
// We embed the label names directly so the orchestrator does not need to import
// the model package.
var defaultLabels = []string{
	"BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Malware",
}

func probabilitiesToJSON(r *classifierv1.ClassifyResponse) string {
	return ch.ProbabilitiesToJSON(defaultLabels, r.Probabilities)
}
