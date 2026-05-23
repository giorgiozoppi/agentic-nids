// Run 'make proto' to generate the classifierv1 package before building.
package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	// Run 'make proto' to generate this package
	classifierv1 "nids/services/gen/classifierv1"
	"nids/services/classifier/internal/model"
)

// Server implements classifierv1.ClassifierServiceServer.
type Server struct {
	classifierv1.UnimplementedClassifierServiceServer
	model  *model.Model
	labels []string
}

// New creates a Server wrapping the given model. labels must be indexed to
// match the model's output columns (use model.DefaultLabels if unsure).
func New(m *model.Model, labels []string) *Server {
	return &Server{model: m, labels: labels}
}

// ClassifyBatch implements the ClassifierService.ClassifyBatch RPC.
func (s *Server) ClassifyBatch(
	ctx context.Context,
	req *classifierv1.ClassifyBatchRequest,
) (*classifierv1.ClassifyBatchResponse, error) {
	if len(req.Flows) == 0 {
		return nil, status.Error(codes.InvalidArgument, "batch must contain at least one flow")
	}

	// Build feature matrix.
	features := make([][]float32, len(req.Flows))
	for i, f := range req.Flows {
		features[i] = model.FlowToFeatures(f)
	}

	// Run inference.
	probMatrix, err := s.model.PredictBatch(features)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "model inference failed: %v", err)
	}

	// Build response.
	results := make([]*classifierv1.ClassifyResponse, len(req.Flows))
	for i, probs := range probMatrix {
		bestIdx := argmax(probs)
		label := "UNKNOWN"
		if bestIdx < len(s.labels) {
			label = s.labels[bestIdx]
		}
		results[i] = &classifierv1.ClassifyResponse{
			FlowId:        req.Flows[i].FlowId,
			Label:         label,
			Confidence:    probs[bestIdx],
			Probabilities: probs,
		}
	}

	return &classifierv1.ClassifyBatchResponse{Results: results}, nil
}

// argmax returns the index of the maximum value in s.
func argmax(s []float32) int {
	if len(s) == 0 {
		return 0
	}
	best := 0
	for i := 1; i < len(s); i++ {
		if s[i] > s[best] {
			best = i
		}
	}
	return best
}
