// Run 'make proto' to generate the classifierv1 package before building.
package model

import (
	"fmt"

	ort "github.com/microsoft/onnxruntime-go"

	// Run 'make proto' to generate this package
	classifierv1 "nids/services/gen/classifierv1"
)

const (
	NumFeatures = 22
	NumClasses  = 8
	MaxBatch    = 256
)

// DefaultLabels is the ordered list of class names output by the model.
// Index i corresponds to column i of the output probability tensor.
var DefaultLabels = []string{
	"BENIGN",
	"DoS",
	"DDoS",
	"PortScan",
	"BruteForce",
	"WebAttack",
	"Botnet",
	"Malware",
}

// Model wraps an ONNX Runtime advanced session with pre-allocated tensors.
type Model struct {
	session     *ort.AdvancedSession
	inputTensor *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
	inputName   string
	outputName  string
}

// New initialises the ORT environment, loads the model from modelPath, and
// pre-allocates input/output tensors for up to MaxBatch rows.
func New(libPath, modelPath string, inputName, outputName string) (*Model, error) {
	ort.SetSharedLibraryPath(libPath)
	if err := ort.InitializeEnvironment(); err != nil {
		return nil, fmt.Errorf("ort init: %w", err)
	}

	inputShape := ort.NewShape(MaxBatch, NumFeatures)
	inputTensor, err := ort.NewEmptyTensor[float32](inputShape)
	if err != nil {
		_ = ort.DestroyEnvironment()
		return nil, fmt.Errorf("create input tensor: %w", err)
	}

	outputShape := ort.NewShape(MaxBatch, NumClasses)
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		_ = inputTensor.Destroy()
		_ = ort.DestroyEnvironment()
		return nil, fmt.Errorf("create output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{inputName},
		[]string{outputName},
		[]ort.ArbitraryTensor{inputTensor},
		[]ort.ArbitraryTensor{outputTensor},
		nil,
	)
	if err != nil {
		_ = inputTensor.Destroy()
		_ = outputTensor.Destroy()
		_ = ort.DestroyEnvironment()
		return nil, fmt.Errorf("new ort session: %w", err)
	}

	return &Model{
		session:      session,
		inputTensor:  inputTensor,
		outputTensor: outputTensor,
		inputName:    inputName,
		outputName:   outputName,
	}, nil
}

// PredictBatch runs inference on a slice of feature vectors and returns the
// output probability rows. len(features) must be > 0 and <= MaxBatch.
func (m *Model) PredictBatch(features [][]float32) ([][]float32, error) {
	n := len(features)
	if n == 0 || n > MaxBatch {
		return nil, fmt.Errorf("batch size %d out of range [1, %d]", n, MaxBatch)
	}

	// Fill the pre-allocated input tensor (row-major).
	data := m.inputTensor.GetData()
	for i, row := range features {
		if len(row) != NumFeatures {
			return nil, fmt.Errorf("row %d: expected %d features, got %d", i, NumFeatures, len(row))
		}
		copy(data[i*NumFeatures:(i+1)*NumFeatures], row)
	}

	// Reshape the tensors to the actual batch size before running.
	if err := m.inputTensor.SetShape(ort.NewShape(int64(n), NumFeatures)); err != nil {
		return nil, fmt.Errorf("reshape input: %w", err)
	}
	if err := m.outputTensor.SetShape(ort.NewShape(int64(n), NumClasses)); err != nil {
		return nil, fmt.Errorf("reshape output: %w", err)
	}

	if err := m.session.Run(); err != nil {
		return nil, fmt.Errorf("ort session run: %w", err)
	}

	outData := m.outputTensor.GetData()
	results := make([][]float32, n)
	for i := 0; i < n; i++ {
		row := make([]float32, NumClasses)
		copy(row, outData[i*NumClasses:(i+1)*NumClasses])
		results[i] = row
	}
	return results, nil
}

// Close destroys the session, tensors, and ORT environment.
func (m *Model) Close() {
	_ = m.session.Destroy()
	_ = m.inputTensor.Destroy()
	_ = m.outputTensor.Destroy()
	_ = ort.DestroyEnvironment()
}

// FlowToFeatures extracts the 22 numeric features from a FlowFeatures proto
// message in the exact order expected by the ONNX model.
func FlowToFeatures(f *classifierv1.FlowFeatures) []float32 {
	return []float32{
		float32(f.BidirectionalDurationMs),   // 1
		float32(f.BidirectionalPackets),       // 2
		float32(f.BidirectionalBytes),         // 3
		float32(f.Src2DstPackets),             // 4
		float32(f.Dst2SrcPackets),             // 5
		float32(f.Src2DstBytes),               // 6
		float32(f.Dst2SrcBytes),               // 7
		f.PacketsPerSecond,                    // 8
		f.BytesPerSecond,                      // 9
		f.BidirectionalMinPs,                  // 10
		f.BidirectionalMeanPs,                 // 11
		f.BidirectionalStddevPs,               // 12
		f.BidirectionalMaxPs,                  // 13
		f.BidirectionalMinPiatMs,              // 14
		f.BidirectionalMeanPiatMs,             // 15
		f.BidirectionalStddevPiatMs,           // 16
		f.BidirectionalMaxPiatMs,              // 17
		float32(f.BidirectionalSynPackets),    // 18
		float32(f.BidirectionalAckPackets),    // 19
		float32(f.BidirectionalPshPackets),    // 20
		float32(f.BidirectionalRstPackets),    // 21
		float32(f.BidirectionalFinPackets),    // 22
	}
}
