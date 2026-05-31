package main

import (
	"testing"
	"time"

	classifierv1 "nids/orchestrator/gen/classifierv1"
	"nids/orchestrator/internal/ch"
)

var testLabels = []string{
	"BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Malware",
}

func baseFlow(id string) ch.Flow {
	return ch.Flow{
		FlowID:                  id,
		SrcIP:                   "10.0.0.1",
		DstIP:                   "10.0.0.2",
		SrcPort:                 50000,
		DstPort:                 80,
		Protocol:                6,
		CollectedAt:             time.Now(),
		BidirectionalDurationMs: 500,
		BidirectionalPackets:    20,
		BidirectionalBytes:      3000,
		PacketsPerSecond:        40,
		BytesPerSecond:          6000,
	}
}

func result(flowID, label string, conf float32) *classifierv1.ClassifyResponse {
	probs := make([]float32, len(testLabels))
	for i, l := range testLabels {
		if l == label {
			probs[i] = conf
		} else {
			probs[i] = (1 - conf) / float32(len(testLabels)-1)
		}
	}
	return &classifierv1.ClassifyResponse{
		FlowId:        flowID,
		Label:         label,
		Confidence:    conf,
		Probabilities: probs,
	}
}

// ---------------------------------------------------------------------------

func TestAugmentFlows_AllClassifiedWritten(t *testing.T) {
	flows := []ch.Flow{baseFlow("f1"), baseFlow("f2"), baseFlow("f3")}
	results := []*classifierv1.ClassifyResponse{
		result("f1", "BENIGN", 0.95),
		result("f2", "DoS", 0.88),
		result("f3", "PortScan", 0.76),
	}

	out := augmentFlows(flows, results, testLabels)

	if len(out.ClassifiedFlows) != 3 {
		t.Errorf("ClassifiedFlows: got %d, want 3", len(out.ClassifiedFlows))
	}
}

func TestAugmentFlows_OnlyThreatsInSecurityEvents(t *testing.T) {
	flows := []ch.Flow{baseFlow("f1"), baseFlow("f2"), baseFlow("f3")}
	results := []*classifierv1.ClassifyResponse{
		result("f1", "BENIGN", 0.95),
		result("f2", "DoS", 0.88),
		result("f3", "BENIGN", 0.91),
	}

	out := augmentFlows(flows, results, testLabels)

	if len(out.SecurityEvents) != 1 {
		t.Errorf("SecurityEvents: got %d, want 1", len(out.SecurityEvents))
	}
	if out.SecurityEvents[0].Label != "DoS" {
		t.Errorf("SecurityEvent label: got %q, want DoS", out.SecurityEvents[0].Label)
	}
}

func TestAugmentFlows_IsThreatFlag(t *testing.T) {
	flows := []ch.Flow{baseFlow("f1"), baseFlow("f2")}
	results := []*classifierv1.ClassifyResponse{
		result("f1", "BENIGN", 0.9),
		result("f2", "Malware", 0.85),
	}

	out := augmentFlows(flows, results, testLabels)

	for _, cf := range out.ClassifiedFlows {
		switch cf.FlowID {
		case "f1":
			if cf.IsThreat != 0 {
				t.Errorf("BENIGN flow should have IsThreat=0, got %d", cf.IsThreat)
			}
		case "f2":
			if cf.IsThreat != 1 {
				t.Errorf("Malware flow should have IsThreat=1, got %d", cf.IsThreat)
			}
		}
	}
}

func TestAugmentFlows_ProbabilitiesPresent(t *testing.T) {
	flows := []ch.Flow{baseFlow("f1")}
	results := []*classifierv1.ClassifyResponse{result("f1", "DDoS", 0.82)}

	out := augmentFlows(flows, results, testLabels)

	cf := out.ClassifiedFlows[0]
	if cf.Probabilities == "" || cf.Probabilities == "{}" {
		t.Error("Probabilities JSON should not be empty")
	}
	// Must contain the predicted label.
	if cf.Probabilities[0] != '{' {
		t.Errorf("Probabilities is not JSON: %s", cf.Probabilities)
	}
}

func TestAugmentFlows_SkipsUnknownFlowIDs(t *testing.T) {
	flows := []ch.Flow{baseFlow("known")}
	results := []*classifierv1.ClassifyResponse{
		result("known", "BENIGN", 0.9),
		result("ghost", "DoS", 0.8), // no matching flow
	}

	out := augmentFlows(flows, results, testLabels)

	if len(out.ClassifiedFlows) != 1 {
		t.Errorf("should skip result with no matching flow, got %d", len(out.ClassifiedFlows))
	}
}

func TestAugmentFlows_AllThreats(t *testing.T) {
	flows := []ch.Flow{baseFlow("a"), baseFlow("b"), baseFlow("c")}
	results := []*classifierv1.ClassifyResponse{
		result("a", "BruteForce", 0.9),
		result("b", "WebAttack", 0.8),
		result("c", "Botnet", 0.75),
	}

	out := augmentFlows(flows, results, testLabels)

	if len(out.SecurityEvents) != 3 {
		t.Errorf("all 3 flows are threats, got %d events", len(out.SecurityEvents))
	}
	if len(out.ClassifiedFlows) != 3 {
		t.Errorf("classified_flows should also have 3 rows, got %d", len(out.ClassifiedFlows))
	}
}

func TestAugmentFlows_EmptyInput(t *testing.T) {
	out := augmentFlows(nil, nil, testLabels)
	if len(out.ClassifiedFlows) != 0 || len(out.SecurityEvents) != 0 {
		t.Error("empty input should produce empty output")
	}
}

func TestAugmentFlows_ConfidenceAndLabelCopied(t *testing.T) {
	flows := []ch.Flow{baseFlow("f1")}
	results := []*classifierv1.ClassifyResponse{result("f1", "PortScan", 0.93)}

	out := augmentFlows(flows, results, testLabels)

	cf := out.ClassifiedFlows[0]
	if cf.Label != "PortScan" {
		t.Errorf("label: got %q, want PortScan", cf.Label)
	}
	if cf.Confidence != 0.93 {
		t.Errorf("confidence: got %f, want 0.93", cf.Confidence)
	}
}
