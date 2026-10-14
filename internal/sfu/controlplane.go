package sfu

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ─────────────────────────────────────────────
// Internal API (SFU → Pufferblow backend)
// ─────────────────────────────────────────────

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// postInternal POSTs payload as JSON to the Pufferblow API's internal
// voice endpoint at path, signed with internal_secret, and returns the
// response status and body.
func (s *Server) postInternal(path string, payload any) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, s.internalAPIBase+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pufferblow-Signature", signPayload(s.internalSecret, body))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, nil
}

// ─────────────────────────────────────────────
// Internal events
// ─────────────────────────────────────────────

type internalEvent struct {
	EventType string
	Payload   map[string]any
}

// emitInternalEvent queues a lifecycle event for the Pufferblow API without
// blocking: if the queue is full the event is dropped (and counted), since
// stalling signaling or media is worse than a missed event.
func (s *Server) emitInternalEvent(eventType string, payload map[string]any) {
	event := internalEvent{EventType: eventType, Payload: payload}
	select {
	case s.eventQueue <- event:
	default:
		s.droppedInternalEvents.Add(1)
		s.log.Warn("internal event dropped: queue full",
			"event_type", eventType,
			"queue_len", len(s.eventQueue),
			"queue_cap", cap(s.eventQueue),
		)
	}
}

func (s *Server) startEventWorkers() {
	for i := 0; i < s.eventWorkers; i++ {
		id := i + 1
		go func(workerID int) {
			s.log.Debug("internal event worker started", "worker_id", workerID)
			for event := range s.eventQueue {
				s.postInternalEvent(event)
			}
			s.log.Debug("internal event worker stopped", "worker_id", workerID)
		}(id)
	}
}

func (s *Server) postInternalEvent(event internalEvent) {
	status, data, err := s.postInternal("/events", map[string]any{
		"event_type": event.EventType,
		"payload":    event.Payload,
	})
	if err != nil {
		s.log.Error("internal event: POST failed",
			"event_type", event.EventType, "err", err)
		return
	}
	if status >= 300 {
		s.log.Warn("internal event: backend rejected event",
			"event_type", event.EventType,
			"status", status,
			"body", string(data),
		)
		return
	}
	s.log.Debug("internal event: delivered",
		"event_type", event.EventType,
		"status", status,
	)
}

// ─────────────────────────────────────────────
// Instance registry heartbeat
// ─────────────────────────────────────────────

func randomInstanceID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "sfu-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "sfu-" + hex.EncodeToString(buf)
}

// startHeartbeatLoop periodically reports this instance's identity and load
// into pufferblow's media_sfu_instances registry so create_or_join_session
// can route new sessions here. A no-op (with a one-time warning) when
// public_signaling_url isn't configured — single-instance deployments don't
// need the registry at all, since pufferblow's own hardcoded signaling_url
// fallback already works for them.
func (s *Server) startHeartbeatLoop() {
	if s.publicSignalingURL == "" {
		s.log.Warn("public_signaling_url not set — skipping instance registry heartbeat (single-instance mode)")
		return
	}

	go func() {
		s.postHeartbeat()
		ticker := time.NewTicker(s.heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.postHeartbeat()
		}
	}()
}

func (s *Server) postHeartbeat() {
	status, data, err := s.postInternal("/instances/heartbeat", map[string]any{
		"instance_id":     s.instanceID,
		"region":          s.region,
		"signaling_url":   s.publicSignalingURL,
		"current_peers":   s.totalPeers.Load(),
		"max_total_peers": s.maxTotalPeers,
	})
	if err != nil {
		s.log.Error("heartbeat: POST failed", "err", err)
		return
	}
	if status >= 300 {
		s.log.Warn("heartbeat: backend rejected heartbeat",
			"status", status, "body", string(data))
		return
	}
	s.log.Debug("heartbeat: delivered", "status", status)
}
