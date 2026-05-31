package main

// augment.go — pure classification-augmentation logic, fully testable without
// any ClickHouse or gRPC connections.

import (
	"nids/orchestrator/internal/ch"

	classifierv1 "nids/orchestrator/gen/classifierv1"
)

// AugmentResult holds the two write targets produced for a single page of flows.
type AugmentResult struct {
	// ClassifiedFlows contains every flow enriched with classifier output.
	// Written to nids.classified_flows regardless of the label.
	ClassifiedFlows []ch.ClassifiedFlow

	// SecurityEvents contains only the non-BENIGN flows.
	// Written to nids.security_events for downstream alerting.
	SecurityEvents []ch.SecurityEvent
}

// augmentFlows enriches raw flows with classifier results, splitting them into
// the two destination tables.  It is a pure function so it can be unit-tested
// without any external services.
func augmentFlows(
	flows []ch.Flow,
	results []*classifierv1.ClassifyResponse,
	labelNames []string,
) AugmentResult {
	// Build a fast lookup: flow_id → Flow.
	byID := make(map[string]ch.Flow, len(flows))
	for _, f := range flows {
		byID[f.FlowID] = f
	}

	out := AugmentResult{
		ClassifiedFlows: make([]ch.ClassifiedFlow, 0, len(results)),
		SecurityEvents:  make([]ch.SecurityEvent, 0),
	}

	for _, r := range results {
		f, ok := byID[r.FlowId]
		if !ok {
			continue
		}

		probJSON := ch.ProbabilitiesToJSON(labelNames, r.Probabilities)
		isThreat := uint8(0)
		if r.Label != "BENIGN" {
			isThreat = 1
		}

		out.ClassifiedFlows = append(out.ClassifiedFlows, ch.ClassifiedFlow{
			FlowID:                  f.FlowID,
			SrcIP:                   f.SrcIP,
			DstIP:                   f.DstIP,
			SrcPort:                 f.SrcPort,
			DstPort:                 f.DstPort,
			Protocol:                f.Protocol,
			CollectedAt:             f.CollectedAt,
			BidirectionalDurationMs: f.BidirectionalDurationMs,
			BidirectionalPackets:    f.BidirectionalPackets,
			BidirectionalBytes:      f.BidirectionalBytes,
			PacketsPerSecond:        f.PacketsPerSecond,
			BytesPerSecond:          f.BytesPerSecond,
			Label:                   r.Label,
			Confidence:              r.Confidence,
			Probabilities:           probJSON,
			IsThreat:                isThreat,
		})

		if isThreat == 1 {
			out.SecurityEvents = append(out.SecurityEvents, ch.SecurityEvent{
				FlowID:                  f.FlowID,
				SrcIP:                   f.SrcIP,
				DstIP:                   f.DstIP,
				SrcPort:                 f.SrcPort,
				DstPort:                 f.DstPort,
				Protocol:                f.Protocol,
				Label:                   r.Label,
				Confidence:              r.Confidence,
				Probabilities:           probJSON,
				BidirectionalPackets:    f.BidirectionalPackets,
				BidirectionalBytes:      f.BidirectionalBytes,
				BidirectionalDurationMs: f.BidirectionalDurationMs,
			})
		}
	}

	return out
}
