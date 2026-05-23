// Package ch provides a ClickHouse client for the orchestrator.
package ch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Flow represents one row from nids.flows.
type Flow struct {
	FlowID                    string
	SrcIP, DstIP              string
	SrcPort, DstPort          uint16
	Protocol                  uint8
	CollectedAt               time.Time
	BidirectionalDurationMs   uint64
	BidirectionalPackets      uint32
	BidirectionalBytes        uint64
	Src2DstPackets            uint32
	Dst2SrcPackets            uint32
	Src2DstBytes              uint64
	Dst2SrcBytes              uint64
	PacketsPerSecond          float64
	BytesPerSecond            float64
	BidirectionalMinPs        float32
	BidirectionalMeanPs       float32
	BidirectionalStddevPs     float32
	BidirectionalMaxPs        float32
	BidirectionalMinPiatMs    float32
	BidirectionalMeanPiatMs   float32
	BidirectionalStddevPiatMs float32
	BidirectionalMaxPiatMs    float32
	BidirectionalSynPackets   uint32
	BidirectionalAckPackets   uint32
	BidirectionalPshPackets   uint32
	BidirectionalRstPackets   uint32
	BidirectionalFinPackets   uint32
}

// SecurityEvent represents one row to insert into nids.security_events.
type SecurityEvent struct {
	FlowID                  string
	SrcIP, DstIP            string
	SrcPort, DstPort        uint16
	Protocol                uint8
	Label                   string
	Confidence              float32
	Probabilities           string // JSON: {"BENIGN":0.9,...}
	BidirectionalPackets    uint32
	BidirectionalBytes      uint64
	BidirectionalDurationMs uint64
}

// Client wraps a ClickHouse native protocol connection.
type Client struct {
	conn driver.Conn
}

// New opens a ClickHouse connection using the native protocol.
func New(addr, database, user, password string) (*Client, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: database,
			Username: user,
			Password: password,
		},
		DialTimeout:  10 * time.Second,
		MaxOpenConns: 4,
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	return &Client{conn: conn}, nil
}

const fetchQuery = `
SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, collected_at,
       bidirectional_duration_ms, bidirectional_packets, bidirectional_bytes,
       src2dst_packets, dst2src_packets, src2dst_bytes, dst2src_bytes,
       packets_per_second, bytes_per_second,
       bidirectional_min_ps, bidirectional_mean_ps, bidirectional_stddev_ps, bidirectional_max_ps,
       bidirectional_min_piat_ms, bidirectional_mean_piat_ms, bidirectional_stddev_piat_ms, bidirectional_max_piat_ms,
       bidirectional_syn_packets, bidirectional_ack_packets, bidirectional_psh_packets,
       bidirectional_rst_packets, bidirectional_fin_packets
FROM nids.flows
WHERE collected_at > ?
ORDER BY collected_at ASC
LIMIT ?
`

// FetchFlows returns up to limit flows collected after since.
func (c *Client) FetchFlows(ctx context.Context, since time.Time, limit int) ([]Flow, error) {
	rows, err := c.conn.Query(ctx, fetchQuery, since, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch flows query: %w", err)
	}
	defer rows.Close()

	var flows []Flow
	for rows.Next() {
		var f Flow
		if err := rows.Scan(
			&f.FlowID, &f.SrcIP, &f.DstIP, &f.SrcPort, &f.DstPort, &f.Protocol, &f.CollectedAt,
			&f.BidirectionalDurationMs, &f.BidirectionalPackets, &f.BidirectionalBytes,
			&f.Src2DstPackets, &f.Dst2SrcPackets, &f.Src2DstBytes, &f.Dst2SrcBytes,
			&f.PacketsPerSecond, &f.BytesPerSecond,
			&f.BidirectionalMinPs, &f.BidirectionalMeanPs, &f.BidirectionalStddevPs, &f.BidirectionalMaxPs,
			&f.BidirectionalMinPiatMs, &f.BidirectionalMeanPiatMs, &f.BidirectionalStddevPiatMs, &f.BidirectionalMaxPiatMs,
			&f.BidirectionalSynPackets, &f.BidirectionalAckPackets, &f.BidirectionalPshPackets,
			&f.BidirectionalRstPackets, &f.BidirectionalFinPackets,
		); err != nil {
			return nil, fmt.Errorf("scan flow row: %w", err)
		}
		flows = append(flows, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate flow rows: %w", err)
	}
	return flows, nil
}

// InsertSecurityEvents bulk-inserts security events using a prepared batch.
func (c *Client) InsertSecurityEvents(ctx context.Context, events []SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := c.conn.PrepareBatch(ctx,
		`INSERT INTO nids.security_events
		 (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
		  label, confidence, probabilities,
		  bidirectional_packets, bidirectional_bytes, bidirectional_duration_ms)
		 VALUES`)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, e := range events {
		if err := batch.Append(
			e.FlowID, e.SrcIP, e.DstIP, e.SrcPort, e.DstPort, e.Protocol,
			e.Label, e.Confidence, e.Probabilities,
			e.BidirectionalPackets, e.BidirectionalBytes, e.BidirectionalDurationMs,
		); err != nil {
			return fmt.Errorf("append event %s: %w", e.FlowID, err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}
	return nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// ProbabilitiesToJSON serialises a label→probability map to a JSON string.
func ProbabilitiesToJSON(labels []string, probs []float32) string {
	m := make(map[string]float32, len(labels))
	for i, l := range labels {
		if i < len(probs) {
			m[l] = probs[i]
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}
