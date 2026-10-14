package sfu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────
// Token / Bootstrap types
// ─────────────────────────────────────────────

// joinClaims are the verified fields extracted from a one-time join token
// issued by the Pufferblow backend. Sub is the user UUID, Scope encodes
// what the peer is allowed to do in this session.
//
// Scope values (space-separated, any combination):
//
//	send_audio   – peer may publish microphone audio
//	send_video   – peer may publish camera / screenshare video
//	recv         – peer may subscribe to other participants' tracks
type joinClaims struct {
	Sub        string `json:"sub"`         // user UUID
	Username   string `json:"username"`    // display name for participant list
	InstanceID string `json:"instance_id"` // originating Pufferblow instance
	ServerID   string `json:"server_id"`   // community / guild ID
	ChannelID  string `json:"channel_id"`  // voice channel UUID
	SessionID  string `json:"session_id"`  // SFU room / session UUID
	Scope      string `json:"scope"`       // space-separated permission flags
	Exp        int64  `json:"exp"`
	Iat        int64  `json:"iat"`
	JTI        string `json:"jti"` // one-time use nonce
}

// hasScope reports whether the claims contain the given permission flag.
func (c *joinClaims) hasScope(flag string) bool {
	for _, s := range strings.Fields(c.Scope) {
		if s == flag {
			return true
		}
	}
	return false
}

type consumeTokenResponse struct {
	StatusCode int        `json:"status_code"`
	Claims     joinClaims `json:"claims"`
	Detail     string     `json:"detail"`
}

// ─────────────────────────────────────────────
// Token validation
// ─────────────────────────────────────────────

func (s *Server) consumeJoinToken(joinToken string) (*joinClaims, error) {
	if strings.TrimSpace(joinToken) == "" {
		return nil, errors.New("missing join token")
	}
	status, data, err := s.postInternal("/consume-join-token", map[string]string{"join_token": joinToken})
	if err != nil {
		return nil, err
	}

	if status != http.StatusOK {
		if len(data) == 0 {
			return nil, fmt.Errorf("join token consume failed: status %d", status)
		}
		return nil, fmt.Errorf("join token consume failed: %s", string(data))
	}

	var decoded consumeTokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	c := &decoded.Claims
	if c.Sub == "" || c.SessionID == "" || c.ChannelID == "" {
		return nil, errors.New("invalid join token claims: missing required fields")
	}
	// Require at least recv scope — a token with no scope is useless and suspicious.
	if !c.hasScope("recv") && !c.hasScope("send_audio") && !c.hasScope("send_video") {
		return nil, errors.New("invalid join token: no valid scope")
	}
	return c, nil
}
