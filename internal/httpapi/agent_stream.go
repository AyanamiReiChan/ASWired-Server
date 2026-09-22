package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
)

// The handshake authenticates the session once; each update still checks the
// current credentials/disabled state. Only telemetry replaces observations.
func (a *App) agentStream(ctx context.Context, conn *websocket.Conn, channel *agentwire.Channel, private string, session agentwire.Report, initial agentwire.Reply) {
	inflight := map[string]bool{}
	for _, cmd := range initial.Commands {
		inflight[cmd.ID] = true
	}
	compression := session.Stream.Compression == "gzip"
	var telemetryBase map[string]any
	var telemetryRevision uint64
	for {
		readCtx, cancel := context.WithTimeout(ctx, 3*agentwire.HeartbeatSeconds*time.Second)
		kind, raw, err := conn.Read(readCtx)
		cancel()
		if err != nil || kind != websocket.MessageBinary {
			return
		}
		var update agentwire.Update
		if channel.OpenBinary(raw, &update, compression) != nil || !update.Valid() {
			return
		}
		if raw[4] != 0 && (update.Kind != "telemetry" || update.Token != "") {
			return
		}
		if update.Token != "" {
			session.Token = update.Token
		}
		if update.Capabilities != nil {
			session.Capabilities = update.Capabilities
		}
		report := session
		report.Observation, report.Results, report.Timestamp = update.Observation, update.Results, update.Timestamp
		var nextObservation map[string]any
		if update.Delta != nil {
			if !session.Stream.TelemetryDelta || telemetryRevision == ^uint64(0) || update.TelemetrySeq != telemetryRevision+1 {
				return
			}
			nextObservation, err = agentwire.ApplyObservationDelta(telemetryRevision, telemetryBase, *update.Delta)
			if err != nil {
				return
			}
			// Accounting normalizes counters in-place. Its input must never be
			// the immutable wire baseline used to reconstruct the next sample.
			report.Observation, err = agentwire.CloneObservation(nextObservation)
			if err != nil {
				return
			}
		} else if session.Stream.TelemetryDelta && update.Kind == "telemetry" {
			return // A negotiated delta stream cannot silently lose its baseline.
		}
		// At most one command batch may be outstanding while heartbeats and
		// telemetry continue during a slow operation.
		report.Busy = update.Busy || len(inflight) > 0
		a.stateMu.RLock()
		var reply agentwire.Reply
		if private != a.MasterPrivate {
			err = errors.New("master identity changed")
		} else {
			reply, err = a.acceptReport(ctx, report, "WebSocket")
		}
		if err == nil {
			for _, result := range update.Results {
				task, readErr := a.DB.GetTask(ctx, result.ID)
				if !errors.Is(readErr, store.ErrNotFound) && (readErr != nil || task.ServerID != session.ServerID || (task.Status != "success" && task.Status != "failed" && task.Status != "unsupported")) {
					err = errors.New("command result was not persisted")
					break
				}
				reply.AckResults = append(reply.AckResults, result.ID)
				delete(inflight, result.ID)
			}
		}
		a.stateMu.RUnlock()
		if err == nil && update.Delta != nil {
			telemetryBase, telemetryRevision = nextObservation, update.TelemetrySeq
			reply.TelemetryAck = telemetryRevision
		}
		if err != nil {
			reply = agentwire.Reply{Error: err.Error()}
		}
		for _, cmd := range reply.Commands {
			inflight[cmd.ID] = true
		}
		// Commands can contain credentials. Do not mix them into compression.
		var payload any = reply
		if session.Stream.TelemetryDelta {
			payload = agentwire.CompactReply(reply, session.ConnectionMode, initial.ListenAddress)
		}
		packet, sealErr := channel.SealBinary(payload, false)
		if sealErr != nil {
			return
		}
		writeCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		writeErr := conn.Write(writeCtx, websocket.MessageBinary, packet)
		stop()
		if err != nil || writeErr != nil {
			return
		}
	}
}
