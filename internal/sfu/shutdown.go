package sfu

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
)

// ─────────────────────────────────────────────
// Graceful shutdown
// ─────────────────────────────────────────────

func (s *Server) shutdown(ctx context.Context) {
	s.log.Info("graceful shutdown initiated")

	// Collect all peers across all rooms.
	s.roomsMu.RLock()
	rooms := make([]*room, 0, len(s.rooms))
	for _, r := range s.rooms {
		rooms = append(rooms, r)
	}
	s.roomsMu.RUnlock()

	// Send close frames and close peer connections.
	for _, r := range rooms {
		r.Mu.RLock()
		peers := make([]*peer, 0, len(r.Peers))
		for _, p := range r.Peers {
			peers = append(peers, p)
		}
		r.Mu.RUnlock()

		for _, p := range peers {
			s.log.Debug("shutdown: closing peer",
				"user_id", p.UserID, "session_id", r.SessionID)
			_ = p.WS.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down"),
				time.Now().Add(2*time.Second),
			)
			_ = p.WS.Close()
			_ = p.PC.Close()

			s.emitInternalEvent("participant_left", map[string]any{
				"session_id": r.SessionID,
				"channel_id": r.ChannelID,
				"user_id":    p.UserID,
				"reason":     "server_shutdown",
			})
		}

		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "server_shutdown",
		})
	}

	// Drain the event queue — give workers up to 10 seconds to flush.
	close(s.eventQueue)
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-drainCtx.Done():
			s.log.Warn("shutdown: event queue drain timed out",
				"remaining", len(s.eventQueue))
			return
		case <-ticker.C:
			if len(s.eventQueue) == 0 {
				s.log.Info("shutdown: event queue drained")
				return
			}
		}
	}
}
