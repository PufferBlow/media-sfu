package sfu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// ─────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────

type roomMetric struct {
	SessionID string `json:"session_id"`
	ChannelID string `json:"channel_id"`
	Peers     int    `json:"peers"`
}

// ─────────────────────────────────────────────
// HTTP handlers
// ─────────────────────────────────────────────

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.healthz)
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/rtc/v1/ws", s.handleWS)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     Version,
		"total_peers": s.totalPeers.Load(),
		"active_rooms": func() int {
			s.roomsMu.RLock()
			defer s.roomsMu.RUnlock()
			return len(s.rooms)
		}(),
	})
	s.log.Debug("healthz", "remote_addr", r.RemoteAddr)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	// Require HMAC signature if metricsSecret is configured.
	if s.metricsSecret != "" {
		sig := r.Header.Get("X-Pufferblow-Signature")
		expected := "sha256=" + func() string {
			mac := hmac.New(sha256.New, []byte(s.metricsSecret))
			mac.Write([]byte(r.URL.Path))
			return hex.EncodeToString(mac.Sum(nil))
		}()
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			s.log.Warn("metrics: unauthorized access attempt", "remote_addr", r.RemoteAddr)
			return
		}
	}

	s.roomsMu.RLock()
	roomMetrics := make([]roomMetric, 0, len(s.rooms))
	for _, rm := range s.rooms {
		roomMetrics = append(roomMetrics, roomMetric{
			SessionID: rm.SessionID,
			ChannelID: rm.ChannelID,
			Peers:     rm.peerCount(),
		})
	}
	s.roomsMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"version":                  Version,
		"active_rooms":             len(roomMetrics),
		"total_peers":              s.totalPeers.Load(),
		"max_total_peers":          s.maxTotalPeers,
		"max_room_peers":           s.maxRoomPeers,
		"room_end_grace_seconds":   int(s.roomEndGrace.Seconds()),
		"total_joins":              s.totalJoins.Load(),
		"total_leaves":             s.totalLeaves.Load(),
		"rejected_connections":     s.rejectedConnections.Load(),
		"dropped_internal_events":  s.droppedInternalEvents.Load(),
		"tracks_fanned":            s.tracksFanned.Load(),
		"internal_event_workers":   s.eventWorkers,
		"internal_event_queue_len": len(s.eventQueue),
		"internal_event_queue_cap": cap(s.eventQueue),
		"media_quality":            s.mediaQuality,
		"rooms":                    roomMetrics,
	})
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
