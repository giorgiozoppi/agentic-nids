package grpcclient_test

import (
	"context"
	"net"
	"testing"

	classifierv1 "nids/orchestrator/gen/classifierv1"
	"nids/orchestrator/internal/ch"
	"nids/orchestrator/internal/grpcclient"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1 << 20

// dummyServer mimics the dummy Rust classifier: picks a label from a fixed
// rotation so tests can assert on the exact returned values.
type dummyServer struct {
	classifierv1.UnimplementedClassifierServiceServer
	labels []string
	call   int
}

func (d *dummyServer) ClassifyBatch(
	_ context.Context,
	req *classifierv1.ClassifyBatchRequest,
) (*classifierv1.ClassifyBatchResponse, error) {
	results := make([]*classifierv1.ClassifyResponse, len(req.Flows))
	for i, f := range req.Flows {
		label := d.labels[d.call%len(d.labels)]
		d.call++
		probs := make([]float32, 8)
		probs[0] = 0.01
		for j := range probs {
			probs[j] = 0.01
		}
		probs[0] = 0.99
		results[i] = &classifierv1.ClassifyResponse{
			FlowId:        f.FlowId,
			Label:         label,
			Confidence:    0.99,
			Probabilities: probs,
		}
	}
	return &classifierv1.ClassifyBatchResponse{Results: results}, nil
}

// startInProcess spins up the dummy gRPC server on an in-memory listener
// and returns a grpcclient.Client connected to it.
func startInProcess(t *testing.T, srv *dummyServer) *grpcclient.Client {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	classifierv1.RegisterClassifierServiceServer(s, srv)

	go func() { _ = s.Serve(lis) }()
	t.Cleanup(func() { s.Stop(); lis.Close() })

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return grpcclient.NewFromConn(conn)
}

// makeFlows creates n minimal ch.Flow values for use in tests.
func makeFlows(n int) []ch.Flow {
	flows := make([]ch.Flow, n)
	for i := range flows {
		flows[i] = ch.Flow{
			FlowID:  "flow-" + string(rune('A'+i)),
			SrcIP:   "10.0.0.1",
			DstIP:   "10.0.0.2",
			SrcPort: 12345,
			DstPort: 80,
		}
	}
	return flows
}

// ---------------------------------------------------------------------------

func TestClassifyBatch_ReturnsSameCountAsInput(t *testing.T) {
	srv := &dummyServer{labels: []string{"BENIGN"}}
	c := startInProcess(t, srv)

	flows := makeFlows(5)
	results, err := c.ClassifyBatch(context.Background(), flows)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != len(flows) {
		t.Errorf("got %d results, want %d", len(results), len(flows))
	}
}

func TestClassifyBatch_PreservesFlowIDs(t *testing.T) {
	srv := &dummyServer{labels: []string{"DoS", "BENIGN"}}
	c := startInProcess(t, srv)

	flows := makeFlows(3)
	results, err := c.ClassifyBatch(context.Background(), flows)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	for i, r := range results {
		if r.FlowId != flows[i].FlowID {
			t.Errorf("result[%d].FlowId = %q, want %q", i, r.FlowId, flows[i].FlowID)
		}
	}
}

func TestClassifyBatch_Empty(t *testing.T) {
	srv := &dummyServer{labels: []string{"BENIGN"}}
	c := startInProcess(t, srv)

	results, err := c.ClassifyBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error on empty input: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil result for empty input, got %v", results)
	}
}

func TestClassifyBatch_LabelsPresent(t *testing.T) {
	srv := &dummyServer{labels: []string{"PortScan", "DDoS", "BENIGN"}}
	c := startInProcess(t, srv)

	flows := makeFlows(3)
	results, err := c.ClassifyBatch(context.Background(), flows)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	want := []string{"PortScan", "DDoS", "BENIGN"}
	for i, r := range results {
		if r.Label != want[i] {
			t.Errorf("result[%d].Label = %q, want %q", i, r.Label, want[i])
		}
		if r.Confidence <= 0 || r.Confidence > 1 {
			t.Errorf("result[%d].Confidence = %f out of [0,1]", i, r.Confidence)
		}
		if len(r.Probabilities) == 0 {
			t.Errorf("result[%d].Probabilities is empty", i)
		}
	}
}

func TestClassifyBatch_LargeBatch(t *testing.T) {
	srv := &dummyServer{labels: []string{"WebAttack"}}
	c := startInProcess(t, srv)

	flows := makeFlows(256)
	results, err := c.ClassifyBatch(context.Background(), flows)
	if err != nil {
		t.Fatalf("ClassifyBatch 256 flows: %v", err)
	}
	if len(results) != 256 {
		t.Errorf("got %d results, want 256", len(results))
	}
}
