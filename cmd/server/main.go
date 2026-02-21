package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

type joinClaims struct {
	Sub        string `json:"sub"`
	InstanceID string `json:"instance_id"`
	ServerID   string `json:"server_id"`
	ChannelID  string `json:"channel_id"`
	SessionID  string `json:"session_id"`
	Scope      string `json:"scope"`
	Exp        int64  `json:"exp"`
	Iat        int64  `json:"iat"`
	JTI        string `json:"jti"`
}

type consumeTokenResponse struct {
	StatusCode int        `json:"status_code"`
	Claims     joinClaims `json:"claims"`
	Detail     string     `json:"detail"`
}

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

type internalEvent struct {
	EventType string
	Payload   map[string]any
}

type participantSnapshot struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username,omitempty"`
	IsMuted     bool   `json:"is_muted"`
	IsDeafened  bool   `json:"is_deafened"`
	IsSpeaking  bool   `json:"is_speaking"`
	ConnectedAt string `json:"connected_at"`
}

type peer struct {
	UserID      string
	Username    string
	SessionID   string
	ChannelID   string
	ConnectedAt time.Time
	IsMuted     bool
	IsDeafened  bool
	IsSpeaking  bool

	WS      *websocket.Conn
	PC      *webrtc.PeerConnection
	WriteMu sync.Mutex

	WriteTimeout time.Duration
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

type room struct {
	SessionID string
	ChannelID string

	Mu     sync.RWMutex
	Peers  map[string]*peer
	Tracks map[string]*webrtc.TrackLocalStaticRTP
}

func (r *room) snapshots() []participantSnapshot {
	r.Mu.RLock()
	defer r.Mu.RUnlock()

	out := make([]participantSnapshot, 0, len(r.Peers))
	for _, p := range r.Peers {
		out = append(out, participantSnapshot{
			UserID:      p.UserID,
			Username:    p.Username,
			IsMuted:     p.IsMuted,
			IsDeafened:  p.IsDeafened,
			IsSpeaking:  p.IsSpeaking,
			ConnectedAt: p.ConnectedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func (r *room) peerCount() int {
	r.Mu.RLock()
	defer r.Mu.RUnlock()
	return len(r.Peers)
}

type roomMetric struct {
	SessionID string `json:"session_id"`
	ChannelID string `json:"channel_id"`
	Peers     int    `json:"peers"`
}

type sfuServer struct {
	bindAddr        string
	internalAPIBase string
	internalSecret  string

	maxTotalPeers int
	maxRoomPeers  int

	readLimit    int64
	writeTimeout time.Duration
	pingInterval time.Duration
	pongWait     time.Duration

	eventWorkers int
	eventQueue   chan internalEvent

	httpClient *http.Client
	webrtcAPI  *webrtc.API
	iceServers []webrtc.ICEServer

	roomsMu sync.RWMutex
	rooms   map[string]*room

	upgrader websocket.Upgrader

	totalPeers            atomic.Int64
	rejectedConnections   atomic.Int64
	droppedInternalEvents atomic.Int64
}

func newServer() *sfuServer {
	minUDPPort := envIntOrDefault("RTC_UDP_PORT_MIN", 50000)
	maxUDPPort := envIntOrDefault("RTC_UDP_PORT_MAX", 50199)
	settingEngine := webrtc.SettingEngine{}
	if minUDPPort > 0 && maxUDPPort >= minUDPPort && maxUDPPort <= 65535 {
		if err := settingEngine.SetEphemeralUDPPortRange(uint16(minUDPPort), uint16(maxUDPPort)); err != nil {
			log.Printf("failed setting UDP port range (%d-%d): %v", minUDPPort, maxUDPPort, err)
		}
	}

	readLimit := int64(envIntOrDefault("RTC_WS_READ_LIMIT_BYTES", 1024*1024))
	writeTimeout := envDurationOrDefault("RTC_WS_WRITE_TIMEOUT", 4*time.Second)
	pongWait := envDurationOrDefault("RTC_WS_PONG_WAIT", 45*time.Second)
	pingInterval := envDurationOrDefault("RTC_WS_PING_INTERVAL", 20*time.Second)
	if pingInterval >= pongWait {
		pingInterval = pongWait / 2
	}

	internalTimeout := envDurationOrDefault("RTC_INTERNAL_HTTP_TIMEOUT", 5*time.Second)
	eventWorkers := envIntOrDefault("RTC_INTERNAL_EVENT_WORKERS", 4)
	if eventWorkers < 1 {
		eventWorkers = 1
	}

	eventQueueSize := envIntOrDefault("RTC_INTERNAL_EVENT_QUEUE_SIZE", 4096)
	if eventQueueSize < 32 {
		eventQueueSize = 32
	}

	return &sfuServer{
		bindAddr:        envOrDefault("RTC_BIND_ADDR", ":8787"),
		internalAPIBase: strings.TrimRight(envOrDefault("RTC_INTERNAL_API_BASE", "http://localhost:7575/api/internal/v1/voice"), "/"),
		internalSecret:  envOrDefault("RTC_INTERNAL_SECRET", ""),
		maxTotalPeers:   envIntOrDefault("RTC_MAX_TOTAL_PEERS", 200),
		maxRoomPeers:    envIntOrDefault("RTC_MAX_ROOM_PEERS", 60),
		readLimit:       readLimit,
		writeTimeout:    writeTimeout,
		pingInterval:    pingInterval,
		pongWait:        pongWait,
		eventWorkers:    eventWorkers,
		eventQueue:      make(chan internalEvent, eventQueueSize),
		httpClient:      &http.Client{Timeout: internalTimeout},
		webrtcAPI:       webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)),
		iceServers:      parseIceServers(),
		rooms:           map[string]*room{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		},
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envIntOrDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid int env %s=%q (using %d)", key, raw, fallback)
		return fallback
	}
	return parsed
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("invalid duration env %s=%q (using %s)", key, raw, fallback)
		return fallback
	}
	return parsed
}

func parseIceServers() []webrtc.ICEServer {
	raw := strings.TrimSpace(os.Getenv("RTC_ICE_SERVERS"))
	if raw == "" {
		return nil
	}

	username := strings.TrimSpace(os.Getenv("RTC_ICE_USERNAME"))
	credential := strings.TrimSpace(os.Getenv("RTC_ICE_CREDENTIAL"))

	entries := strings.Split(raw, ",")
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		url := strings.TrimSpace(entry)
		if url == "" {
			continue
		}

		server := webrtc.ICEServer{URLs: []string{url}}
		if username != "" {
			server.Username = username
		}
		if credential != "" {
			server.Credential = credential
		}
		servers = append(servers, server)
	}
	return servers
}

func (s *sfuServer) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *sfuServer) metrics(w http.ResponseWriter, _ *http.Request) {
	s.roomsMu.RLock()
	roomMetrics := make([]roomMetric, 0, len(s.rooms))
	for _, roomObj := range s.rooms {
		roomMetrics = append(roomMetrics, roomMetric{
			SessionID: roomObj.SessionID,
			ChannelID: roomObj.ChannelID,
			Peers:     roomObj.peerCount(),
		})
	}
	s.roomsMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"active_rooms":             len(roomMetrics),
		"total_peers":              s.totalPeers.Load(),
		"max_total_peers":          s.maxTotalPeers,
		"max_room_peers":           s.maxRoomPeers,
		"rejected_connections":     s.rejectedConnections.Load(),
		"dropped_internal_events":  s.droppedInternalEvents.Load(),
		"internal_event_workers":   s.eventWorkers,
		"internal_event_queue_len": len(s.eventQueue),
		"rooms":                    roomMetrics,
	})
}

func (s *sfuServer) getOrCreateRoom(sessionID, channelID string) *room {
	s.roomsMu.Lock()
	defer s.roomsMu.Unlock()

	r, ok := s.rooms[sessionID]
	if ok {
		return r
	}

	r = &room{
		SessionID: sessionID,
		ChannelID: channelID,
		Peers:     map[string]*peer{},
		Tracks:    map[string]*webrtc.TrackLocalStaticRTP{},
	}
	s.rooms[sessionID] = r
	return r
}

func (s *sfuServer) deleteRoomIfEmpty(r *room) {
	r.Mu.RLock()
	empty := len(r.Peers) == 0
	r.Mu.RUnlock()
	if !empty {
		return
	}

	s.roomsMu.Lock()
	delete(s.rooms, r.SessionID)
	s.roomsMu.Unlock()
}

func (s *sfuServer) reservePeerSlot() bool {
	if s.maxTotalPeers <= 0 {
		s.totalPeers.Add(1)
		return true
	}

	for {
		current := s.totalPeers.Load()
		if int(current) >= s.maxTotalPeers {
			return false
		}
		if s.totalPeers.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (s *sfuServer) releasePeerSlot() {
	s.totalPeers.Add(-1)
}

func (s *sfuServer) startEventWorkers() {
	for i := 0; i < s.eventWorkers; i++ {
		workerID := i + 1
		go s.internalEventWorker(workerID)
	}
}

func (s *sfuServer) internalEventWorker(workerID int) {
	log.Printf("internal-event-worker-%d started", workerID)
	for event := range s.eventQueue {
		s.postInternalEvent(event)
	}
}

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *sfuServer) consumeJoinToken(joinToken string) (*joinClaims, error) {
	if strings.TrimSpace(joinToken) == "" {
		return nil, errors.New("missing join token")
	}

	body, _ := json.Marshal(map[string]string{"join_token": joinToken})
	endpoint := s.internalAPIBase + "/consume-join-token"

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pufferblow-Signature", signPayload(s.internalSecret, body))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if len(data) == 0 {
			return nil, fmt.Errorf("join token consume failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("join token consume failed: %s", string(data))
	}

	var decoded consumeTokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	if decoded.Claims.Sub == "" || decoded.Claims.SessionID == "" || decoded.Claims.ChannelID == "" {
		return nil, errors.New("invalid join token claims payload")
	}

	return &decoded.Claims, nil
}

func (s *sfuServer) postInternalEvent(event internalEvent) {
	body, _ := json.Marshal(map[string]any{
		"event_type": event.EventType,
		"payload":    event.Payload,
	})
	endpoint := s.internalAPIBase + "/events"

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("internal event request build failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pufferblow-Signature", signPayload(s.internalSecret, body))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("internal event post failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		log.Printf("internal event rejected status=%d body=%s", resp.StatusCode, string(data))
	}
}

func (s *sfuServer) emitInternalEvent(eventType string, payload map[string]any) {
	event := internalEvent{
		EventType: eventType,
		Payload:   payload,
	}

	select {
	case s.eventQueue <- event:
	default:
		s.droppedInternalEvents.Add(1)
		log.Printf("dropping internal event due full queue event_type=%s", eventType)
	}
}

func (s *sfuServer) addTrackToPeer(target *peer, track *webrtc.TrackLocalStaticRTP) error {
	sender, err := target.PC.AddTrack(track)
	if err != nil {
		return err
	}

	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, readErr := sender.Read(rtcpBuf); readErr != nil {
				return
			}
		}
	}()

	offer, err := target.PC.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := target.PC.SetLocalDescription(offer); err != nil {
		return err
	}
	if err := target.send(signalMessage{
		Type:      "offer",
		SessionID: target.SessionID,
		Offer:     &offer,
	}); err != nil {
		return err
	}
	return nil
}

func (s *sfuServer) handleRemoteTrack(r *room, srcPeer *peer, remoteTrack *webrtc.TrackRemote) {
	trackKey := fmt.Sprintf("%s:%s", srcPeer.UserID, remoteTrack.ID())
	localTrack, err := webrtc.NewTrackLocalStaticRTP(
		remoteTrack.Codec().RTPCodecCapability,
		fmt.Sprintf("%s-%s", srcPeer.UserID, remoteTrack.ID()),
		"pufferblow",
	)
	if err != nil {
		log.Printf("failed to create local RTP track: %v", err)
		return
	}

	r.Mu.Lock()
	r.Tracks[trackKey] = localTrack
	peers := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		if p.UserID == srcPeer.UserID {
			continue
		}
		peers = append(peers, p)
	}
	r.Mu.Unlock()

	for _, target := range peers {
		if err := s.addTrackToPeer(target, localTrack); err != nil {
			log.Printf("failed to fanout track %s to %s: %v", trackKey, target.UserID, err)
		}
	}

	for {
		rtpPacket, _, readErr := remoteTrack.ReadRTP()
		if readErr != nil {
			break
		}
		if writeErr := localTrack.WriteRTP(rtpPacket); writeErr != nil {
			break
		}
	}

	r.Mu.Lock()
	delete(r.Tracks, trackKey)
	r.Mu.Unlock()
}

func (s *sfuServer) removePeer(r *room, p *peer, reason string) {
	r.Mu.Lock()
	_, exists := r.Peers[p.UserID]
	if exists {
		delete(r.Peers, p.UserID)
	}
	remaining := len(r.Peers)
	r.Mu.Unlock()

	if !exists {
		return
	}

	_ = p.PC.Close()
	_ = p.WS.Close()
	s.releasePeerSlot()

	s.emitInternalEvent("participant_left", map[string]any{
		"session_id": r.SessionID,
		"channel_id": r.ChannelID,
		"user_id":    p.UserID,
		"reason":     reason,
	})

	s.broadcastRoom(r, signalMessage{
		Type:      "participant_left",
		SessionID: r.SessionID,
		Payload: map[string]any{
			"user_id":           p.UserID,
			"participant_count": remaining,
		},
	}, p.UserID)

	if remaining == 0 {
		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "empty",
		})
		s.deleteRoomIfEmpty(r)
	}
}

func (s *sfuServer) broadcastRoom(r *room, msg signalMessage, exceptUserID string) {
	r.Mu.RLock()
	peers := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		if exceptUserID != "" && p.UserID == exceptUserID {
			continue
		}
		peers = append(peers, p)
	}
	r.Mu.RUnlock()

	for _, p := range peers {
		if err := p.send(msg); err != nil {
			log.Printf("broadcast error to user=%s: %v", p.UserID, err)
		}
	}
}

func (s *sfuServer) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}
	conn.SetReadLimit(s.readLimit)
	_ = conn.SetReadDeadline(time.Now().Add(s.pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(s.pongWait))
		return nil
	})

	joinToken := r.URL.Query().Get("join_token")
	claims, err := s.consumeJoinToken(joinToken)
	if err != nil {
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: err.Error()})
		_ = conn.Close()
		return
	}

	if !s.reservePeerSlot() {
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "server at capacity"})
		_ = conn.Close()
		return
	}

	roomObj := s.getOrCreateRoom(claims.SessionID, claims.ChannelID)
	if s.maxRoomPeers > 0 && roomObj.peerCount() >= s.maxRoomPeers {
		s.rejectedConnections.Add(1)
		s.releasePeerSlot()
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "voice room is full"})
		_ = conn.Close()
		return
	}

	peerObj := &peer{
		UserID:       claims.Sub,
		Username:     claims.Sub,
		SessionID:    claims.SessionID,
		ChannelID:    claims.ChannelID,
		ConnectedAt:  time.Now().UTC(),
		WS:           conn,
		WriteTimeout: s.writeTimeout,
	}

	pc, err := s.webrtcAPI.NewPeerConnection(webrtc.Configuration{
		ICEServers: s.iceServers,
	})
	if err != nil {
		s.releasePeerSlot()
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "failed to initialize peer connection"})
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

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		candidate := c.ToJSON()
		_ = peerObj.send(signalMessage{
			Type:      "candidate",
			SessionID: roomObj.SessionID,
			Candidate: &candidate,
		})
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateDisconnected {
			s.removePeer(roomObj, peerObj, state.String())
		}
	})

	pc.OnTrack(func(remoteTrack *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		s.handleRemoteTrack(roomObj, peerObj, remoteTrack)
	})

	var existingTracks []*webrtc.TrackLocalStaticRTP
	roomObj.Mu.Lock()
	if s.maxRoomPeers > 0 && len(roomObj.Peers) >= s.maxRoomPeers {
		roomObj.Mu.Unlock()
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "voice room is full"})
		return
	}
	if _, exists := roomObj.Peers[peerObj.UserID]; exists {
		roomObj.Mu.Unlock()
		s.rejectedConnections.Add(1)
		_ = conn.WriteJSON(signalMessage{Type: "error", Error: "user already connected in this session"})
		return
	}
	existingTracks = make([]*webrtc.TrackLocalStaticRTP, 0, len(roomObj.Tracks))
	for _, existingTrack := range roomObj.Tracks {
		existingTracks = append(existingTracks, existingTrack)
	}
	roomObj.Peers[peerObj.UserID] = peerObj
	peerCount := len(roomObj.Peers)
	roomObj.Mu.Unlock()
	joinedRoom = true

	for _, existingTrack := range existingTracks {
		if err := s.addTrackToPeer(peerObj, existingTrack); err != nil {
			log.Printf("failed adding existing track to new peer: %v", err)
		}
	}

	s.emitInternalEvent("participant_joined", map[string]any{
		"session_id": roomObj.SessionID,
		"channel_id": roomObj.ChannelID,
		"user_id":    peerObj.UserID,
		"username":   peerObj.Username,
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
			"participant_count": peerCount,
		},
	}, peerObj.UserID)

	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(s.pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := peerObj.sendControl(websocket.PingMessage, []byte("ping")); err != nil {
					_ = peerObj.WS.Close()
					return
				}
			case <-stopPing:
				return
			}
		}
	}()

	for {
		_, raw, readErr := conn.ReadMessage()
		if readErr != nil {
			break
		}

		var msg signalMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			_ = peerObj.send(signalMessage{Type: "error", Error: "invalid signaling payload"})
			continue
		}

		switch msg.Type {
		case "join":
			_ = peerObj.send(signalMessage{
				Type:         "joined",
				SessionID:    roomObj.SessionID,
				Participants: roomObj.snapshots(),
			})
		case "offer":
			if msg.Offer == nil {
				continue
			}
			if err := peerObj.PC.SetRemoteDescription(*msg.Offer); err != nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply offer"})
				continue
			}

			answer, err := peerObj.PC.CreateAnswer(nil)
			if err != nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to create answer"})
				continue
			}
			if err := peerObj.PC.SetLocalDescription(answer); err != nil {
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
				continue
			}
			if err := peerObj.PC.SetRemoteDescription(*msg.Answer); err != nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to apply answer"})
			}
		case "candidate":
			if msg.Candidate == nil {
				continue
			}
			if err := peerObj.PC.AddICECandidate(*msg.Candidate); err != nil {
				_ = peerObj.send(signalMessage{Type: "error", Error: "failed to add ICE candidate"})
			}
		case "audio_state":
			if msg.AudioState != nil {
				if v, ok := msg.AudioState["is_muted"].(bool); ok {
					peerObj.IsMuted = v
				}
				if v, ok := msg.AudioState["is_deafened"].(bool); ok {
					peerObj.IsDeafened = v
				}
				if v, ok := msg.AudioState["is_speaking"].(bool); ok {
					peerObj.IsSpeaking = v
				}

				s.emitInternalEvent("state_changed", map[string]any{
					"session_id":  roomObj.SessionID,
					"channel_id":  roomObj.ChannelID,
					"user_id":     peerObj.UserID,
					"is_muted":    peerObj.IsMuted,
					"is_deafened": peerObj.IsDeafened,
					"is_speaking": peerObj.IsSpeaking,
				})

				s.broadcastRoom(roomObj, signalMessage{
					Type:      "speaker_levels",
					SessionID: roomObj.SessionID,
					Payload: map[string]any{
						"user_id":     peerObj.UserID,
						"is_speaking": peerObj.IsSpeaking,
						"is_muted":    peerObj.IsMuted,
					},
				}, "")
			}
		case "ping":
			_ = peerObj.send(signalMessage{Type: "pong", SessionID: roomObj.SessionID})
		default:
			_ = peerObj.send(signalMessage{Type: "error", Error: "unsupported signaling message type"})
		}
	}

	close(stopPing)
	s.removePeer(roomObj, peerObj, "client_disconnect")
}

func main() {
	server := newServer()
	if strings.TrimSpace(server.internalSecret) == "" {
		log.Fatal("RTC_INTERNAL_SECRET is required")
	}
	server.startEventWorkers()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.healthz)
	mux.HandleFunc("/readyz", server.healthz)
	mux.HandleFunc("/metrics", server.metrics)
	mux.HandleFunc("/rtc/v1/ws", server.handleWS)

	httpServer := &http.Server{
		Addr:              server.bindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf(
		"media-sfu listening on %s (max_total_peers=%d max_room_peers=%d workers=%d)",
		server.bindAddr,
		server.maxTotalPeers,
		server.maxRoomPeers,
		server.eventWorkers,
	)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("media-sfu server error: %v", err)
	}
}
