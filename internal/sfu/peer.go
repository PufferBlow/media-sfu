package sfu

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

// ─────────────────────────────────────────────
// Participant snapshot (sent to clients)
// ─────────────────────────────────────────────

type participantSnapshot struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username,omitempty"`
	IsMuted    bool   `json:"is_muted"`
	IsDeafened bool   `json:"is_deafened"`
	IsSpeaking bool   `json:"is_speaking"`
	// IsSharingScreen lets a newcomer learn "user X is already publishing
	// a screen share track" at join time, so the client can bind the
	// incoming video track to user X without waiting for a separate
	// screen_share_started broadcast that already fired before they joined.
	IsSharingScreen bool   `json:"is_sharing_screen"`
	Scope           string `json:"scope"`
	ConnectedAt     string `json:"connected_at"`
}

// ─────────────────────────────────────────────
// Peer
// ─────────────────────────────────────────────

type peer struct {
	UserID      string
	Username    string
	SessionID   string
	ChannelID   string
	Scope       string // raw scope string from token
	ConnectedAt time.Time

	WS      *websocket.Conn
	PC      *webrtc.PeerConnection
	WriteMu sync.Mutex

	WriteTimeout time.Duration

	// Negotiation state. The SFU offers whenever a track is added to the peer, and several tracks can
	// arrive at once, so offers are sent one at a time (negMu) and a request that comes in while one is
	// unanswered is remembered (renegotiate) and sent when the answer lands.
	negMu       sync.Mutex
	renegotiate bool
	// ICE candidates that arrived before the remote description they belong to; applied once it is set.
	candMu            sync.Mutex
	pendingCandidates []webrtc.ICECandidateInit

	// State fields — guarded by stateMu, NOT the room lock.
	// Separating this mutex avoids holding the room lock during snapshot
	// iteration while audio_state messages are being processed concurrently.
	stateMu         sync.RWMutex
	IsMuted         bool
	IsDeafened      bool
	IsSpeaking      bool
	IsSharingScreen bool
}

func (p *peer) send(msg signalMessage) error {
	p.WriteMu.Lock()
	defer p.WriteMu.Unlock()
	if p.WriteTimeout > 0 {
		_ = p.WS.SetWriteDeadline(time.Now().Add(p.WriteTimeout))
	}
	return p.WS.WriteJSON(msg)
}

func (p *peer) sendControl(messageType int, data []byte) error {
	p.WriteMu.Lock()
	defer p.WriteMu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	if p.WriteTimeout > 0 {
		deadline = time.Now().Add(p.WriteTimeout)
	}
	_ = p.WS.SetWriteDeadline(deadline)
	return p.WS.WriteControl(messageType, data, deadline)
}

// snapshot returns a copy of the peer's current participant state.
// Safe to call without holding the room lock.
func (p *peer) snapshot() participantSnapshot {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return participantSnapshot{
		UserID:          p.UserID,
		Username:        p.Username,
		IsMuted:         p.IsMuted,
		IsDeafened:      p.IsDeafened,
		IsSpeaking:      p.IsSpeaking,
		IsSharingScreen: p.IsSharingScreen,
		Scope:           p.Scope,
		ConnectedAt:     p.ConnectedAt.UTC().Format(time.RFC3339),
	}
}

// isDeafened reports whether the peer has muted all incoming audio on
// their end. Safe to call without the room lock.
func (p *peer) isDeafened() bool {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.IsDeafened
}

// setSharingScreen atomically updates the screen-share flag. Returns true
// if the value changed (i.e. the caller should broadcast). Idempotent so
// a client re-sending screen_share_started during a reconnect doesn't
// emit duplicate broadcasts.
func (p *peer) setSharingScreen(sharing bool) (changed bool) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.IsSharingScreen != sharing {
		p.IsSharingScreen = sharing
		changed = true
	}
	return
}

// setState updates the peer's audio state fields under the state lock.
// Returns true if anything changed.
func (p *peer) setState(muted, deafened, speaking bool) (changed bool) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.IsMuted != muted || p.IsDeafened != deafened || p.IsSpeaking != speaking {
		p.IsMuted = muted
		p.IsDeafened = deafened
		p.IsSpeaking = speaking
		changed = true
	}
	return
}
