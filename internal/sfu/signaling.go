package sfu

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
// WebSocket handler
// ─────────────────────────────────────────────

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	s.log.Debug("ws: new connection attempt", "remote_addr", remoteAddr)

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("ws: upgrade failed", "remote_addr", remoteAddr, "err", err)
		return
	}
	conn.SetReadLimit(s.readLimit)
	_ = conn.SetReadDeadline(time.Now().Add(s.pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(s.pongWait))
		return nil
	})

	// ── Token validation ─────────────────────────────
	joinToken := r.URL.Query().Get("join_token")
	claims, err := s.consumeJoinToken(joinToken)
	if err != nil {
		s.log.Warn("ws: token validation failed",
			"remote_addr", remoteAddr, "err", err)
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "invalid join token"})
		_ = conn.Close()
		return
	}

	s.log.Info("ws: token validated",
		"remote_addr", remoteAddr,
		"user_id", claims.Sub,
		"username", claims.Username,
		"session_id", claims.SessionID,
		"channel_id", claims.ChannelID,
		"scope", claims.Scope,
	)

	// ── Capacity checks ──────────────────────────────
	if !s.reservePeerSlot() {
		s.rejectedConnections.Add(1)
		s.log.Warn("ws: rejected — server at capacity",
			"user_id", claims.Sub,
			"total_peers", s.totalPeers.Load(),
			"max_total_peers", s.maxTotalPeers,
		)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "server at capacity"})
		_ = conn.Close()
		return
	}

	roomObj, created := s.getOrCreateRoom(claims.SessionID, claims.ChannelID)
	s.cancelRoomEndTimer(claims.SessionID)

	if created {
		s.log.Info("room created",
			"session_id", claims.SessionID,
			"channel_id", claims.ChannelID,
		)
	}

	if s.maxRoomPeers > 0 && roomObj.peerCount() >= s.maxRoomPeers {
		s.rejectedConnections.Add(1)
		s.releasePeerSlot()
		s.log.Warn("ws: rejected — room full",
			"user_id", claims.Sub,
			"session_id", claims.SessionID,
			"room_peers", roomObj.peerCount(),
			"max_room_peers", s.maxRoomPeers,
		)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "voice room is full"})
		_ = conn.Close()
		return
	}

	// ── Build peer ───────────────────────────────────
	peerObj := &peer{
		UserID:       claims.Sub,
		Username:     claims.Username,
		SessionID:    claims.SessionID,
		ChannelID:    claims.ChannelID,
		Scope:        claims.Scope,
		ConnectedAt:  time.Now().UTC(),
		WS:           conn,
		WriteTimeout: s.writeTimeout,
	}
	// Default to muted if the token does not grant send_audio
	peerObj.IsMuted = !claims.hasScope("send_audio")

	pc, err := s.webrtcAPI.NewPeerConnection(webrtc.Configuration{
		ICEServers: s.iceServers,
	})
	if err != nil {
		s.releasePeerSlot()
		s.log.Error("ws: failed to create peer connection",
			"user_id", claims.Sub, "err", err)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "failed to initialise peer connection"})
		_ = conn.Close()
		return
	}
	peerObj.PC = pc

	joinedRoom := false
	defer func() {
		if !joinedRoom {
			s.releasePeerSlot()
			_ = conn.Close()
			_ = pc.Close()
		}
	}()

	// ── ICE candidate forwarding ─────────────────────
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		cand := c.ToJSON()
		s.log.Debug("ICE candidate gathered",
			"user_id", peerObj.UserID, "candidate", c.String())
		_ = peerObj.send(signalMessage{
			Type:      "candidate",
			SessionID: roomObj.SessionID,
			Candidate: &cand,
		})
	})

	// ── Connection state changes ─────────────────────
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		s.log.Info("peer connection state changed",
			"user_id", peerObj.UserID,
			"session_id", peerObj.SessionID,
			"state", state.String(),
		)
		switch state {
		case webrtc.PeerConnectionStateFailed,
			webrtc.PeerConnectionStateClosed,
			webrtc.PeerConnectionStateDisconnected:
			s.removePeer(roomObj, peerObj, state.String())
		case webrtc.PeerConnectionStateConnected:
			s.log.Info("peer WebRTC connected",
				"user_id", peerObj.UserID,
				"session_id", peerObj.SessionID,
			)
		}
	})

	// ── Incoming tracks — enforce scope ─────────────
	pc.OnTrack(func(remoteTrack *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		kind := remoteTrack.Kind().String() // "audio" or "video"

		// Check scope before accepting the track.
		allowed := false
		switch kind {
		case "audio":
			allowed = claims.hasScope("send_audio")
		case "video":
			allowed = claims.hasScope("send_video")
		}

		if !allowed {
			s.log.Warn("track rejected: peer lacks scope",
				"user_id", peerObj.UserID,
				"kind", kind,
				"scope", claims.Scope,
			)
			// Drain the track so the peer connection doesn't stall
			go func() {
				buf := make([]byte, 1500)
				for {
					if _, _, err := remoteTrack.Read(buf); err != nil {
						return
					}
				}
			}()
			return
		}

		go s.handleRemoteTrack(roomObj, peerObj, remoteTrack)
	})

	// ── Register peer in room ────────────────────────
	var existingTracks []*roomTrack
	roomObj.Mu.Lock()
	// Re-check capacity under the room lock (authoritative check).
	if s.maxRoomPeers > 0 && len(roomObj.Peers) >= s.maxRoomPeers {
		roomObj.Mu.Unlock()
		s.rejectedConnections.Add(1)
		s.log.Warn("ws: rejected — room full (lock check)",
			"user_id", claims.Sub, "session_id", claims.SessionID)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "voice room is full"})
		return
	}
	if _, exists := roomObj.Peers[peerObj.UserID]; exists {
		roomObj.Mu.Unlock()
		s.rejectedConnections.Add(1)
		s.log.Warn("ws: rejected — user already in session",
			"user_id", claims.Sub, "session_id", claims.SessionID)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "already connected in this session"})
		return
	}
	existingTracks = make([]*roomTrack, 0, len(roomObj.Tracks))
	for _, t := range roomObj.Tracks {
		existingTracks = append(existingTracks, t)
	}
	roomObj.Peers[peerObj.UserID] = peerObj
	peerCount := len(roomObj.Peers)
	roomObj.Mu.Unlock()
	joinedRoom = true

	s.totalJoins.Add(1)
	s.log.Info("peer joined room",
		"user_id", peerObj.UserID,
		"username", peerObj.Username,
		"session_id", roomObj.SessionID,
		"channel_id", roomObj.ChannelID,
		"scope", peerObj.Scope,
		"peer_count", peerCount,
		"existing_tracks", len(existingTracks),
	)

	// Fan existing tracks to the new peer in parallel — skipped entirely if
	// the new peer joined already deafened (see the symmetric skip in
	// handleRemoteTrack for why).
	if len(existingTracks) > 0 && !peerObj.isDeafened() {
		var wg sync.WaitGroup
		for _, t := range existingTracks {
			wg.Add(1)
			go func(track *roomTrack) {
				defer wg.Done()
				if err := s.addTrackToPeer(peerObj, track); err != nil {
					s.log.Warn("failed to add existing track to new peer",
						"user_id", peerObj.UserID, "err", err)
				}
			}(t)
		}
		wg.Wait()
	}

	// Emit join event to backend.
	s.emitInternalEvent("participant_joined", map[string]any{
		"session_id":  roomObj.SessionID,
		"channel_id":  roomObj.ChannelID,
		"user_id":     peerObj.UserID,
		"username":    peerObj.Username,
		"scope":       peerObj.Scope,
		"peer_count":  peerCount,
		"instance_id": claims.InstanceID,
		"server_id":   claims.ServerID,
	})

	// Send joined confirmation with current participant list.
	_ = peerObj.send(signalMessage{
		Type:         "joined",
		SessionID:    roomObj.SessionID,
		Participants: roomObj.snapshots(),
	})

	// Announce new peer to existing participants.
	s.broadcastRoom(roomObj, signalMessage{
		Type:      "participant_joined",
		SessionID: roomObj.SessionID,
		Payload: map[string]any{
			"user_id":           peerObj.UserID,
			"username":          peerObj.Username,
			"scope":             peerObj.Scope,
			"participant_count": peerCount,
		},
	}, peerObj.UserID)

	// ── Ping keepalive goroutine ─────────────────────
	pingStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(s.pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := peerObj.sendControl(websocket.PingMessage, []byte("ping")); err != nil {
					s.log.Debug("ping failed, closing connection",
						"user_id", peerObj.UserID, "err", err)
					_ = peerObj.WS.Close()
					return
				}
			case <-pingStop:
				return
			}
		}
	}()

	// ── Signalling read loop ─────────────────────────
	//
	// Labelled so a graceful `leave` message can break the outer for-loop
	// from inside the switch — plain `break` from a Go switch only exits
	// the case, not the surrounding for. Falling out drops into the
	// cleanup block below (close pingStop + removePeer), which is what
	// we want when a client politely tells us it's done.
readLoop:
	for {
		_, raw, readErr := conn.ReadMessage()
		if readErr != nil {
			s.log.Debug("ws: read error (connection closing)",
				"user_id", peerObj.UserID,
				"session_id", peerObj.SessionID,
				"err", readErr,
			)
			break
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

		switch msg.Type {

		case "join":
			// Idempotent — client may re-send join to refresh participant list.
			_ = peerObj.send(signalMessage{
				Type:         "joined",
				SessionID:    roomObj.SessionID,
				Participants: roomObj.snapshots(),
			})

		case "offer":
			if msg.Offer == nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "offer is null"})
				continue
			}
			if err := peerObj.PC.SetRemoteDescription(*msg.Offer); err != nil {
				s.log.Warn("failed to apply offer",
					"user_id", peerObj.UserID, "err", err)
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply offer"})
				continue
			}
			answer, err := peerObj.PC.CreateAnswer(nil)
			if err != nil {
				s.log.Warn("failed to create answer",
					"user_id", peerObj.UserID, "err", err)
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to create answer"})
				continue
			}
			if err := peerObj.PC.SetLocalDescription(answer); err != nil {
				s.log.Warn("failed to set local description",
					"user_id", peerObj.UserID, "err", err)
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to set local description"})
				continue
			}
			_ = peerObj.send(signalMessage{
				Type:      "answer",
				SessionID: roomObj.SessionID,
				Answer:    &answer,
			})

		case "answer":
			if msg.Answer == nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "answer is null"})
				continue
			}
			if err := peerObj.PC.SetRemoteDescription(*msg.Answer); err != nil {
				s.log.Warn("failed to apply answer",
					"user_id", peerObj.UserID, "err", err)
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply answer"})
			}

		case "candidate":
			if msg.Candidate == nil {
				continue
			}
			if err := peerObj.PC.AddICECandidate(*msg.Candidate); err != nil {
				s.log.Warn("failed to add ICE candidate",
					"user_id", peerObj.UserID, "err", err)
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to add ICE candidate"})
			}

		case "audio_state":
			if msg.AudioState == nil {
				continue
			}

			newMuted := peerObj.IsMuted
			newDeafened := peerObj.IsDeafened
			newSpeaking := peerObj.IsSpeaking

			if v, ok := msg.AudioState["is_muted"].(bool); ok {
				// A server-muted peer cannot unmute themselves.
				// The backend must issue a new token with send_audio to re-enable.
				if !v || claims.hasScope("send_audio") {
					newMuted = v
				}
			}
			if v, ok := msg.AudioState["is_deafened"].(bool); ok {
				newDeafened = v
			}
			if v, ok := msg.AudioState["is_speaking"].(bool); ok {
				newSpeaking = v
			}

			changed := peerObj.setState(newMuted, newDeafened, newSpeaking)
			if !changed {
				continue
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

		case "screen_share_started", "screen_share_stopped":
			// Screen-share announce. Carries no payload from the client —
			// the message type itself is the signal. The SFU enforces
			// send_video at OnTrack time, so a malicious client without
			// send_video scope can still announce but their actual video
			// track will be rejected. That's fine: the announce is just
			// a hint for other clients to bind incoming video tracks to
			// the right user.
			sharing := msg.Type == "screen_share_started"
			if !peerObj.setSharingScreen(sharing) {
				// Already in this state — no-op, no broadcast. Lets the
				// client re-send safely (e.g. after a reconnect) without
				// causing duplicate UI events.
				continue
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
				Type:      msg.Type,
				SessionID: roomObj.SessionID,
				Payload: map[string]any{
					"user_id":  peerObj.UserID,
					"username": peerObj.Username,
				},
			}, peerObj.UserID)

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
			break readLoop

		default:
			s.log.Warn("ws: unsupported message type",
				"user_id", peerObj.UserID,
				"type", msg.Type,
			)
			_ = peerObj.send(signalMessage{Type: "error", Error: "unsupported message type: " + msg.Type})
		}
	}

	// ── Cleanup ──────────────────────────────────────
	close(pingStop)
	s.removePeer(roomObj, peerObj, "client_disconnect")
}
