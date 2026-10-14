package sfu

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

// ─────────────────────────────────────────────
// WebSocket connection lifecycle
// ─────────────────────────────────────────────

// handleWS serves one peer for the lifetime of its signaling WebSocket:
// validate the join token, admit it into the room, run the signaling read
// loop, and remove it when the socket closes or the client sends `leave`.
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

	claims, ok := s.authenticate(conn, r.URL.Query().Get("join_token"), remoteAddr)
	if !ok {
		return
	}

	// From here on the peer holds a global slot, released on every exit
	// path until it has actually joined the room (removePeer owns it then).
	roomObj, ok := s.admit(conn, claims)
	if !ok {
		return
	}

	peerObj, err := s.newPeer(conn, claims, roomObj)
	if err != nil {
		s.releasePeerSlot()
		s.log.Error("ws: failed to create peer connection",
			"user_id", claims.Sub, "err", err)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "failed to initialise peer connection"})
		_ = conn.Close()
		return
	}

	existingTracks, peerCount, err := s.joinRoom(roomObj, peerObj)
	if err != nil {
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: err.Error()})
		s.releasePeerSlot()
		_ = conn.Close()
		_ = peerObj.PC.Close()
		return
	}

	s.announceJoin(roomObj, peerObj, claims, existingTracks, peerCount)

	pingStop := s.keepAlive(peerObj)
	s.readSignals(roomObj, peerObj, claims)

	close(pingStop)
	s.removePeer(roomObj, peerObj, "client_disconnect")
}

// authenticate consumes the one-time join token with the Pufferblow API.
// On failure it tells the client, closes the socket and returns false.
func (s *Server) authenticate(conn *websocket.Conn, joinToken, remoteAddr string) (*joinClaims, bool) {
	claims, err := s.consumeJoinToken(joinToken)
	if err != nil {
		s.log.Warn("ws: token validation failed",
			"remote_addr", remoteAddr, "err", err)
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "invalid join token"})
		_ = conn.Close()
		return nil, false
	}

	s.log.Info("ws: token validated",
		"remote_addr", remoteAddr,
		"user_id", claims.Sub,
		"username", claims.Username,
		"session_id", claims.SessionID,
		"channel_id", claims.ChannelID,
		"scope", claims.Scope,
	)
	return claims, true
}

// admit reserves a global peer slot and finds (or creates) the session's
// room, rejecting the connection if the server or the room is full. The
// room check here is optimistic; joinRoom re-checks it under the room lock.
// On success the caller owns the reserved slot.
func (s *Server) admit(conn *websocket.Conn, claims *joinClaims) (*room, bool) {
	if !s.reservePeerSlot() {
		s.rejectedConnections.Add(1)
		s.log.Warn("ws: rejected — server at capacity",
			"user_id", claims.Sub,
			"total_peers", s.totalPeers.Load(),
			"max_total_peers", s.maxTotalPeers,
		)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "server at capacity"})
		_ = conn.Close()
		return nil, false
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
		return nil, false
	}

	return roomObj, true
}

// newPeer builds the peer and its PeerConnection, wired to forward ICE
// candidates, remove the peer when the connection drops, and accept only
// the tracks its scope allows.
func (s *Server) newPeer(conn *websocket.Conn, claims *joinClaims, roomObj *room) (*peer, error) {
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
		return nil, err
	}
	peerObj.PC = pc

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

	pc.OnTrack(func(remoteTrack *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		kind := remoteTrack.Kind().String() // "audio" or "video"

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

	return peerObj, nil
}

// joinRoom registers the peer in the room, re-checking capacity under the
// room lock (the authoritative check), and returns the tracks already live
// in the room plus the new peer count. The returned error's text is what
// the client is told.
func (s *Server) joinRoom(roomObj *room, peerObj *peer) ([]*roomTrack, int, error) {
	roomObj.Mu.Lock()
	defer roomObj.Mu.Unlock()

	if s.maxRoomPeers > 0 && len(roomObj.Peers) >= s.maxRoomPeers {
		s.log.Warn("ws: rejected — room full (lock check)",
			"user_id", peerObj.UserID, "session_id", peerObj.SessionID)
		return nil, 0, errors.New("voice room is full")
	}
	if _, exists := roomObj.Peers[peerObj.UserID]; exists {
		s.log.Warn("ws: rejected — user already in session",
			"user_id", peerObj.UserID, "session_id", peerObj.SessionID)
		return nil, 0, errors.New("already connected in this session")
	}

	existingTracks := make([]*roomTrack, 0, len(roomObj.Tracks))
	for _, t := range roomObj.Tracks {
		existingTracks = append(existingTracks, t)
	}
	roomObj.Peers[peerObj.UserID] = peerObj
	return existingTracks, len(roomObj.Peers), nil
}

// announceJoin finishes a join: fans the room's live tracks to the new
// peer, reports the join to the Pufferblow API, confirms it to the peer
// and tells everyone else.
func (s *Server) announceJoin(roomObj *room, peerObj *peer, claims *joinClaims, existingTracks []*roomTrack, peerCount int) {
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

	_ = peerObj.send(signalMessage{
		Type:         "joined",
		SessionID:    roomObj.SessionID,
		Participants: roomObj.snapshots(),
	})

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
}

// keepAlive pings the peer's socket every pingInterval until the returned
// channel is closed, closing the socket if a ping can't be written (which
// in turn ends the read loop).
func (s *Server) keepAlive(peerObj *peer) chan<- struct{} {
	stop := make(chan struct{})
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
			case <-stop:
				return
			}
		}
	}()
	return stop
}
