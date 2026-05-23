// Run 'make proto' to generate the classifierv1 package before building.
package grpcclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	// Run 'make proto' to generate this package
	classifierv1 "nids/services/gen/classifierv1"
	"nids/services/orchestrator/internal/ch"
)

// Client wraps a gRPC connection to the classifier service.
type Client struct {
	conn *grpc.ClientConn
	svc  classifierv1.ClassifierServiceClient
}

// New dials the classifier gRPC server at addr using insecure credentials,
// with automatic retries and keepalive settings suitable for a K8s cluster.
func New(addr string) (*Client, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultServiceConfig(`{
			"methodConfig": [{
				"name": [{"service": "nids.classifier.v1.ClassifierService"}],
				"retryPolicy": {
					"maxAttempts": 3,
					"initialBackoff": "0.5s",
					"maxBackoff": "5s",
					"backoffMultiplier": 2,
					"retryableStatusCodes": ["UNAVAILABLE"]
				}
			}]
		}`),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial %s: %w", addr, err)
	}
	return &Client{
		conn: conn,
		svc:  classifierv1.NewClassifierServiceClient(conn),
	}, nil
}

// ClassifyBatch converts a slice of ch.Flow into FlowFeatures protos, calls
// the remote ClassifyBatch RPC, and returns the response slice.
func (c *Client) ClassifyBatch(ctx context.Context, flows []ch.Flow) ([]*classifierv1.ClassifyResponse, error) {
	if len(flows) == 0 {
		return nil, nil
	}

	protos := make([]*classifierv1.FlowFeatures, len(flows))
	for i, f := range flows {
		protos[i] = flowToProto(f)
	}

	resp, err := c.svc.ClassifyBatch(ctx, &classifierv1.ClassifyBatchRequest{Flows: protos})
	if err != nil {
		return nil, fmt.Errorf("ClassifyBatch rpc: %w", err)
	}
	return resp.Results, nil
}

// Close tears down the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// flowToProto maps a ch.Flow struct to a classifierv1.FlowFeatures proto.
func flowToProto(f ch.Flow) *classifierv1.FlowFeatures {
	return &classifierv1.FlowFeatures{
		FlowId:                  f.FlowID,
		SrcIp:                   f.SrcIP,
		DstIp:                   f.DstIP,
		SrcPort:                 uint32(f.SrcPort),
		DstPort:                 uint32(f.DstPort),
		Protocol:                uint32(f.Protocol),
		BidirectionalDurationMs: f.BidirectionalDurationMs,
		BidirectionalPackets:    f.BidirectionalPackets,
		BidirectionalBytes:      f.BidirectionalBytes,
		Src2DstPackets:          f.Src2DstPackets,
		Dst2SrcPackets:          f.Dst2SrcPackets,
		Src2DstBytes:            f.Src2DstBytes,
		Dst2SrcBytes:            f.Dst2SrcBytes,
		PacketsPerSecond:        float32(f.PacketsPerSecond),
		BytesPerSecond:          float32(f.BytesPerSecond),
		BidirectionalMinPs:      f.BidirectionalMinPs,
		BidirectionalMeanPs:     f.BidirectionalMeanPs,
		BidirectionalStddevPs:   f.BidirectionalStddevPs,
		BidirectionalMaxPs:      f.BidirectionalMaxPs,
		BidirectionalMinPiatMs:  f.BidirectionalMinPiatMs,
		BidirectionalMeanPiatMs: f.BidirectionalMeanPiatMs,
		BidirectionalStddevPiatMs: f.BidirectionalStddevPiatMs,
		BidirectionalMaxPiatMs:  f.BidirectionalMaxPiatMs,
		BidirectionalSynPackets: f.BidirectionalSynPackets,
		BidirectionalAckPackets: f.BidirectionalAckPackets,
		BidirectionalPshPackets: f.BidirectionalPshPackets,
		BidirectionalRstPackets: f.BidirectionalRstPackets,
		BidirectionalFinPackets: f.BidirectionalFinPackets,
	}
}
