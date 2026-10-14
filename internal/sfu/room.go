package sfu

import (
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// Room
// ─────────────────────────────────────────────

type room struct {
	SessionID string
	ChannelID string

	Mu     sync.RWMutex
	Peers  map[string]*peer
	Tracks map[string]*roomTrack
}

func (r *room) snapshots() []participantSnapshot {
	r.Mu.RLock()
	peers := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		peers = append(peers, p)
	}
	r.Mu.RUnlock()

	// Build snapshots outside the room lock — each peer has its own stateMu.
	out := make([]participantSnapshot, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.snapshot())
	}
	return out
}

func (r *room) peerCount() int {
	r.Mu.RLock()
	defer r.Mu.RUnlock()
	return len(r.Peers)
}

// ─────────────────────────────────────────────
// Room lifecycle
// ─────────────────────────────────────────────

func (s *Server) getOrCreateRoom(sessionID, channelID string) (*room, bool) {
	s.roomsMu.Lock()
	defer s.roomsMu.Unlock()
	r, ok := s.rooms[sessionID]
	if ok {
		return r, false // existing
	}
	r = &room{
		SessionID: sessionID,
		ChannelID: channelID,
		Peers:     map[string]*peer{},
		Tracks:    map[string]*roomTrack{},
	}
	s.rooms[sessionID] = r
	s.totalRooms.Add(1)
	return r, true // created
}

func (s *Server) deleteRoomIfEmpty(r *room) {
	r.Mu.RLock()
	empty := len(r.Peers) == 0
	r.Mu.RUnlock()
	if !empty {
		return
	}
	s.roomsMu.Lock()
	delete(s.rooms, r.SessionID)
	if t := s.roomEnd[r.SessionID]; t != nil {
		t.Stop()
	}
	delete(s.roomEnd, r.SessionID)
	s.roomsMu.Unlock()

	s.log.Info("room deleted", "session_id", r.SessionID, "channel_id", r.ChannelID)
}

func (s *Server) cancelRoomEndTimer(sessionID string) {
	s.roomsMu.Lock()
	if t := s.roomEnd[sessionID]; t != nil {
		t.Stop()
	}
	delete(s.roomEnd, sessionID)
	s.roomsMu.Unlock()
}

func (s *Server) scheduleRoomEndGrace(r *room) {
	if r.peerCount() > 0 {
		s.cancelRoomEndTimer(r.SessionID)
		return
	}
	if s.roomEndGrace <= 0 {
		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "empty",
		})
		s.deleteRoomIfEmpty(r)
		return
	}

	s.cancelRoomEndTimer(r.SessionID)
	s.log.Debug("scheduling room end grace",
		"session_id", r.SessionID, "grace", s.roomEndGrace)

	t := time.AfterFunc(s.roomEndGrace, func() {
		if r.peerCount() > 0 {
			return
		}
		s.log.Info("room end grace elapsed — session ending",
			"session_id", r.SessionID, "channel_id", r.ChannelID)
		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "empty_grace_timeout",
		})
		s.deleteRoomIfEmpty(r)
	})

	s.roomsMu.Lock()
	s.roomEnd[r.SessionID] = t
	s.roomsMu.Unlock()
}

// ─────────────────────────────────────────────
// Peer removal
// ─────────────────────────────────────────────

func (s *Server) removePeer(r *room, p *peer, reason string) {
	r.Mu.Lock()
	_, exists := r.Peers[p.UserID]
	if exists {
		delete(r.Peers, p.UserID)
	}
	remaining := len(r.Peers)
	r.Mu.Unlock()

	if !exists {
		// Already removed — removePeer is called from both OnConnectionStateChange
		// (multiple states can fire) and the read-loop exit. Only the first call acts.
		return
	}

	_ = p.PC.Close()
	_ = p.WS.Close()
	s.releasePeerSlot()
	s.totalLeaves.Add(1)

	snap := p.snapshot()
	s.log.Info("peer removed",
		"session_id", r.SessionID,
		"channel_id", r.ChannelID,
		"user_id", p.UserID,
		"username", p.Username,
		"reason", reason,
		"remaining_peers", remaining,
		"connected_for", time.Since(p.ConnectedAt).Round(time.Second),
	)

	s.emitInternalEvent("participant_left", map[string]any{
		"session_id": r.SessionID,
		"channel_id": r.ChannelID,
		"user_id":    p.UserID,
		"username":   p.Username,
		"reason":     reason,
		"was_muted":  snap.IsMuted,
	})

	// If the departing peer was publishing a screen share, tell everyone
	// else to tear down their remote video tile. participant_left alone
	// isn't enough because clients use that to update participant lists
	// — the dedicated stop signal is what unbinds the video element.
	if snap.IsSharingScreen {
		s.broadcastRoom(r, signalMessage{
			Type:      "screen_share_stopped",
			SessionID: r.SessionID,
			Payload: map[string]any{
				"user_id":  p.UserID,
				"username": p.Username,
				"reason":   "disconnect",
			},
		}, p.UserID)
	}

	s.broadcastRoom(r, signalMessage{
		Type:      "participant_left",
		SessionID: r.SessionID,
		Payload: map[string]any{
			"user_id":           p.UserID,
			"participant_count": remaining,
		},
	}, p.UserID)

	if remaining == 0 {
		s.scheduleRoomEndGrace(r)
	}
}

// ─────────────────────────────────────────────
// Broadcast
// ─────────────────────────────────────────────

func (s *Server) broadcastRoom(r *room, msg signalMessage, exceptUserID string) {
	r.Mu.RLock()
	peers := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		if exceptUserID == "" || p.UserID != exceptUserID {
			peers = append(peers, p)
		}
	}
	r.Mu.RUnlock()

	for _, p := range peers {
		if err := p.send(msg); err != nil {
			s.log.Warn("broadcast send failed",
				"session_id", r.SessionID,
				"target_user_id", p.UserID,
				"err", err,
			)
		}
	}
}
