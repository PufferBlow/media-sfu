package sfu

import (
	"encoding/json"

	"github.com/pion/webrtc/v4"
)

// ─────────────────────────────────────────────
// Signal message types (client ↔ SFU WebSocket)
// ─────────────────────────────────────────────

type signalMessage struct {
	Type         string                     `json:"type"`
	SessionID    string                     `json:"session_id,omitempty"`
	Offer        *webrtc.SessionDescription `json:"offer,omitempty"`
	Answer       *webrtc.SessionDescription `json:"answer,omitempty"`
	Candidate    *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
	AudioState   map[string]any             `json:"audio_state,omitempty"`
	Participants []participantSnapshot      `json:"participants,omitempty"`
	Payload      map[string]any             `json:"payload,omitempty"`
	Error        string                     `json:"error,omitempty"`
}

// ─────────────────────────────────────────────
// Signaling read loop
// ─────────────────────────────────────────────

// readSignals handles the peer's signaling messages until the socket
// errors (closed, timed out) or the client sends `leave`.
func (s *Server) readSignals(roomObj *room, peerObj *peer, claims *joinClaims) {
	for {
		_, raw, readErr := peerObj.WS.ReadMessage()
		if readErr != nil {
			s.log.Debug("ws: read error (connection closing)",
				"user_id", peerObj.UserID,
				"session_id", peerObj.SessionID,
				"err", readErr,
			)
			return
		}

		var msg signalMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.log.Warn("ws: invalid signalling payload",
				"user_id", peerObj.UserID, "err", err)
			_ = peerObj.send(signalMessage{Type: "error", Error: "invalid signalling payload"})
			continue
		}

		s.log.Debug("ws: received message",
			"user_id", peerObj.UserID,
			"session_id", peerObj.SessionID,
			"type", msg.Type,
		)

		if leave := s.handleSignal(roomObj, peerObj, claims, msg); leave {
			return
		}
	}
}

// handleSignal dispatches one client message. It returns true when the
// client asked to leave, which ends the read loop.
func (s *Server) handleSignal(roomObj *room, peerObj *peer, claims *joinClaims, msg signalMessage) (leave bool) {
	switch msg.Type {
	case "join":
		// Idempotent — client may re-send join to refresh participant list.
		_ = peerObj.send(signalMessage{
			Type:         "joined",
			SessionID:    roomObj.SessionID,
			Participants: roomObj.snapshots(),
		})

	case "offer":
		s.handleOffer(roomObj, peerObj, msg.Offer)

	case "answer":
		s.handleAnswer(peerObj, msg.Answer)

	case "candidate":
		s.handleCandidate(peerObj, msg.Candidate)

	case "audio_state":
		s.handleAudioState(roomObj, peerObj, claims, msg.AudioState)

	case "screen_share_started", "screen_share_stopped":
		s.handleScreenShare(roomObj, peerObj, msg.Type)

	case "ping":
		_ = peerObj.send(signalMessage{Type: "pong", SessionID: roomObj.SessionID})

	case "leave":
		// Client-initiated graceful exit. Without this case the SFU
		// can only detect a departure by the WS close-frame reaching
		// the read loop — which in tab-close / browser-quit
		// scenarios can lag several seconds behind the user's
		// intent, leaving the peer visible in everyone else's
		// participant list as a ghost. An explicit signal lets us
		// remove + broadcast `participant_left` immediately, then
		// drop into the standard cleanup path.
		//
		// Ack is best-effort: by the time the client receives it
		// they've usually already closed their socket. We send it
		// anyway so cooperating clients can wait-for-ack before
		// tearing down their UI on slow connections.
		s.log.Debug("ws: explicit leave received",
			"user_id", peerObj.UserID,
			"session_id", peerObj.SessionID,
		)
		_ = peerObj.send(signalMessage{Type: "leave_ack", SessionID: roomObj.SessionID})
		return true

	default:
		s.log.Warn("ws: unsupported message type",
			"user_id", peerObj.UserID,
			"type", msg.Type,
		)
		_ = peerObj.send(signalMessage{Type: "error", Error: "unsupported message type: " + msg.Type})
	}
	return false
}

// ─────────────────────────────────────────────
// SDP / ICE negotiation
// ─────────────────────────────────────────────

// handleOffer applies a client-initiated offer and replies with an answer.
func (s *Server) handleOffer(roomObj *room, peerObj *peer, offer *webrtc.SessionDescription) {
	if offer == nil {
		_ = peerObj.send(signalMessage{Type: "error", Error: "offer is null"})
		return
	}
	// Both sides can offer at the same moment (the SFU offers when it adds a track). The SFU holds its
	// own offer: the client is told to roll back, answers it, and sends its offer again afterwards.
	// Dropping this one is not an error, so the client is not told it is.
	defer s.renegotiateIfNeeded(peerObj) // runs after the lock below is released
	peerObj.negMu.Lock()
	defer peerObj.negMu.Unlock()
	if peerObj.PC.SignalingState() != webrtc.SignalingStateStable {
		s.log.Debug("ignoring client offer: an offer of ours is unanswered", "user_id", peerObj.UserID)
		return
	}
	if err := peerObj.PC.SetRemoteDescription(*offer); err != nil {
		s.log.Warn("failed to apply offer",
			"user_id", peerObj.UserID, "err", err)
		_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply offer"})
		return
	}
	s.flushCandidates(peerObj)
	answer, err := peerObj.PC.CreateAnswer(nil)
	if err != nil {
		s.log.Warn("failed to create answer",
			"user_id", peerObj.UserID, "err", err)
		_ = peerObj.send(signalMessage{Type: "error", Error: "failed to create answer"})
		return
	}
	if err := peerObj.PC.SetLocalDescription(answer); err != nil {
		s.log.Warn("failed to set local description",
			"user_id", peerObj.UserID, "err", err)
		_ = peerObj.send(signalMessage{Type: "error", Error: "failed to set local description"})
		return
	}
	_ = peerObj.send(signalMessage{
		Type:      "answer",
		SessionID: roomObj.SessionID,
		Answer:    &answer,
	})
}

// handleAnswer applies the client's answer to an offer the SFU sent when
// fanning a track out to it (see addTrackToPeer).
func (s *Server) handleAnswer(peerObj *peer, answer *webrtc.SessionDescription) {
	if answer == nil {
		_ = peerObj.send(signalMessage{Type: "error", Error: "answer is null"})
		return
	}
	if err := peerObj.PC.SetRemoteDescription(*answer); err != nil {
		s.log.Warn("failed to apply answer",
			"user_id", peerObj.UserID, "err", err)
		_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply answer"})
		return
	}
	s.flushCandidates(peerObj)
	// A track may have been added while this offer was out; offer again for it.
	s.renegotiateIfNeeded(peerObj)
}

// Limits on candidates held before the client's offer. A real browser gathers a few dozen at most.
const (
	maxPendingCandidates = 64
	maxCandidateBytes    = 1024
)

// handleCandidate adds a candidate from the client. Candidates can arrive before the offer they belong
// to (the client trickles them as it gathers), so they wait until the remote description is set.
func (s *Server) handleCandidate(peerObj *peer, candidate *webrtc.ICECandidateInit) {
	if candidate == nil {
		return
	}
	if len(candidate.Candidate) > maxCandidateBytes {
		s.log.Warn("dropping oversized ICE candidate", "user_id", peerObj.UserID, "bytes", len(candidate.Candidate))
		return
	}
	peerObj.candMu.Lock()
	if peerObj.PC.RemoteDescription() == nil {
		// A client that never sends its offer must not be able to grow this without bound.
		if len(peerObj.pendingCandidates) < maxPendingCandidates {
			peerObj.pendingCandidates = append(peerObj.pendingCandidates, *candidate)
		} else {
			s.log.Warn("dropping ICE candidate: too many held before the offer", "user_id", peerObj.UserID)
		}
		peerObj.candMu.Unlock()
		return
	}
	peerObj.candMu.Unlock()
	s.addCandidate(peerObj, *candidate)
}

func (s *Server) addCandidate(peerObj *peer, candidate webrtc.ICECandidateInit) {
	if err := peerObj.PC.AddICECandidate(candidate); err != nil {
		s.log.Warn("failed to add ICE candidate",
			"user_id", peerObj.UserID, "err", err)
	}
}

// flushCandidates applies the candidates that arrived early.
func (s *Server) flushCandidates(peerObj *peer) {
	peerObj.candMu.Lock()
	queued := peerObj.pendingCandidates
	peerObj.pendingCandidates = nil
	peerObj.candMu.Unlock()
	for _, candidate := range queued {
		s.addCandidate(peerObj, candidate)
	}
}

// ─────────────────────────────────────────────
// Participant state
// ─────────────────────────────────────────────

// handleAudioState applies a mute/deafen/speaking update and, if anything
// changed, reports it to the Pufferblow API and the whole room.
func (s *Server) handleAudioState(roomObj *room, peerObj *peer, claims *joinClaims, state map[string]any) {
	if state == nil {
		return
	}

	// Only this goroutine writes the peer's state, so reading it here
	// without stateMu is safe.
	newMuted := peerObj.IsMuted
	newDeafened := peerObj.IsDeafened
	newSpeaking := peerObj.IsSpeaking

	if v, ok := state["is_muted"].(bool); ok {
		// A server-muted peer cannot unmute themselves.
		// The backend must issue a new token with send_audio to re-enable.
		if !v || claims.hasScope("send_audio") {
			newMuted = v
		}
	}
	if v, ok := state["is_deafened"].(bool); ok {
		newDeafened = v
	}
	if v, ok := state["is_speaking"].(bool); ok {
		newSpeaking = v
	}

	if !peerObj.setState(newMuted, newDeafened, newSpeaking) {
		return
	}

	s.log.Debug("peer audio state updated",
		"user_id", peerObj.UserID,
		"is_muted", newMuted,
		"is_deafened", newDeafened,
		"is_speaking", newSpeaking,
	)

	s.emitInternalEvent("state_changed", map[string]any{
		"session_id":  roomObj.SessionID,
		"channel_id":  roomObj.ChannelID,
		"user_id":     peerObj.UserID,
		"is_muted":    newMuted,
		"is_deafened": newDeafened,
		"is_speaking": newSpeaking,
	})

	s.broadcastRoom(roomObj, signalMessage{
		Type:      "speaker_levels",
		SessionID: roomObj.SessionID,
		Payload: map[string]any{
			"user_id":     peerObj.UserID,
			"is_speaking": newSpeaking,
			"is_muted":    newMuted,
			"is_deafened": newDeafened,
		},
	}, "")
}

// handleScreenShare handles screen_share_started / screen_share_stopped.
// The message carries no payload from the client — the type itself is the
// signal. The SFU enforces send_video at OnTrack time, so a client without
// send_video scope can still announce but their actual video track will be
// rejected. That's fine: the announce is just a hint for other clients to
// bind incoming video tracks to the right user.
func (s *Server) handleScreenShare(roomObj *room, peerObj *peer, messageType string) {
	sharing := messageType == "screen_share_started"
	if !peerObj.setSharingScreen(sharing) {
		// Already in this state — no-op, no broadcast. Lets the
		// client re-send safely (e.g. after a reconnect) without
		// causing duplicate UI events.
		return
	}

	s.log.Debug("peer screen share state changed",
		"user_id", peerObj.UserID,
		"is_sharing_screen", sharing,
	)

	s.emitInternalEvent("screen_share_changed", map[string]any{
		"session_id":        roomObj.SessionID,
		"channel_id":        roomObj.ChannelID,
		"user_id":           peerObj.UserID,
		"is_sharing_screen": sharing,
	})

	// Broadcast to everyone else in the room. The sender already
	// knows they started, so exclude them.
	s.broadcastRoom(roomObj, signalMessage{
		Type:      messageType,
		SessionID: roomObj.SessionID,
		Payload: map[string]any{
			"user_id":  peerObj.UserID,
			"username": peerObj.Username,
		},
	}, peerObj.UserID)
}
