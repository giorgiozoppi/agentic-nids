//go:build e2e

// E2E smoke test: launches the real classifier binary and verifies the
// gRPC client can classify a batch of flows through it.
//
// Run with:
//   CLASSIFIER_BIN=../../classifier/target/release/classifier \
//   go test ./internal/grpcclient/... -tags e2e -v -run TestE2E
package grpcclient_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"nids/orchestrator/internal/ch"
	"nids/orchestrator/internal/grpcclient"
)

func TestE2EClassifierComm(t *testing.T) {
	bin := os.Getenv("CLASSIFIER_BIN")
	if bin == "" {
		bin = "../../classifier/target/release/classifier"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("classifier binary not found at %s — run 'make build-classifier' first", bin)
	}

	// Pick a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	// Start classifier subprocess.
	cmd := exec.Command(bin, "--addr", addr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start classifier: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// Wait for the gRPC server to accept connections (up to 5 s).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	client, err := grpcclient.New(addr)
	if err != nil {
		t.Fatalf("grpcclient.New(%s): %v", addr, err)
	}
	defer client.Close()

	flows := []ch.Flow{
		{FlowID: "e2e-flow-1", SrcIP: "192.168.1.1", DstIP: "8.8.8.8", SrcPort: 55000, DstPort: 443},
		{FlowID: "e2e-flow-2", SrcIP: "10.0.0.5",    DstIP: "1.1.1.1", SrcPort: 60000, DstPort: 53},
		{FlowID: "e2e-flow-3", SrcIP: "172.16.0.1",  DstIP: "172.16.0.254", SrcPort: 22, DstPort: 22},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := client.ClassifyBatch(ctx, flows)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != len(flows) {
		t.Fatalf("got %d results, want %d", len(results), len(flows))
	}

	validLabels := map[string]bool{
		"BENIGN": true, "DoS": true, "DDoS": true, "PortScan": true,
		"BruteForce": true, "WebAttack": true, "Botnet": true, "Malware": true,
	}
	for _, r := range results {
		if !validLabels[r.Label] {
			t.Errorf("unknown label %q for flow %s", r.Label, r.FlowId)
		}
		if r.Confidence <= 0 || r.Confidence > 1 {
			t.Errorf("confidence %f out of range for flow %s", r.Confidence, r.FlowId)
		}
		t.Logf("  %s → %s (%.2f)", r.FlowId, r.Label, r.Confidence)
	}
	fmt.Printf("\nE2E: classifier at %s classified %d flows successfully\n", addr, len(results))
}
