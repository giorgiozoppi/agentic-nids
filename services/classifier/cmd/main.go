// Run 'make proto' to generate the classifierv1 package before building.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	// Run 'make proto' to generate this package
	classifierv1 "nids/services/gen/classifierv1"
	"nids/services/classifier/internal/model"
	"nids/services/classifier/internal/server"
)

func main() {
	addr        := flag.String("addr",        ":50051",                      "gRPC listen address")
	modelPath   := flag.String("model",       "/models/classifier.onnx",     "path to ONNX model file")
	ortLib      := flag.String("ort-lib",     "/usr/lib/libonnxruntime.so",  "path to ONNX Runtime shared library")
	inputName   := flag.String("input-name",  "float_input",                 "ONNX model input tensor name")
	outputName  := flag.String("output-name", "probabilities",               "ONNX model output tensor name")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("loading ONNX model",
		"lib", *ortLib,
		"model", *modelPath,
		"input", *inputName,
		"output", *outputName,
	)

	m, err := model.New(*ortLib, *modelPath, *inputName, *outputName)
	if err != nil {
		slog.Error("failed to load model", "error", err)
		os.Exit(1)
	}
	defer m.Close()

	svc := server.New(m, model.DefaultLabels)

	grpcServer := grpc.NewServer()
	classifierv1.RegisterClassifierServiceServer(grpcServer, svc)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "addr", *addr, "error", err)
		os.Exit(1)
	}

	slog.Info("classifier gRPC server starting", "addr", *addr)

	// Handle graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-quit
		slog.Info("received signal, stopping", "signal", fmt.Sprintf("%v", sig))
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server exited with error", "error", err)
		os.Exit(1)
	}

	slog.Info("classifier server stopped")
}
