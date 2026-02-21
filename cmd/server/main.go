package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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

	"github.com/BurntSushi/toml"
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

type bootstrapIceServer struct {
	URLs       any    `json:"urls"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

type sfuBootstrapConfig struct {
	InternalAPIBase        string               `json:"internal_api_base"`
	InternalSecret         string               `json:"internal_secret"`
	MaxTotalPeers          int                  `json:"max_total_peers"`
	MaxRoomPeers           int                  `json:"max_room_peers"`
	RoomEndGraceSeconds    int                  `json:"room_end_grace_seconds"`
	InternalEventWorkers   int                  `json:"internal_event_workers"`
	InternalEventQueueSize int                  `json:"internal_event_queue_size"`
	InternalHTTPTimeoutSec int                  `json:"internal_http_timeout_seconds"`
	WSWriteTimeoutSec      int                  `json:"ws_write_timeout_seconds"`
	WSPingIntervalSec      int                  `json:"ws_ping_interval_seconds"`
	WSPongWaitSec          int                  `json:"ws_pong_wait_seconds"`
	WSReadLimitBytes       int                  `json:"ws_read_limit_bytes"`
	UDPPortMin             int                  `json:"udp_port_min"`
	UDPPortMax             int                  `json:"udp_port_max"`
	IceServers             []bootstrapIceServer `json:"ice_servers"`
}

type bootstrapConfigResponse struct {
	StatusCode int                `json:"status_code"`
	Config     sfuBootstrapConfig `json:"config"`
	Detail     string             `json:"detail"`
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

// MediaSFUConfig represents the [media-sfu] section from config.toml
type MediaSFUConfig struct {
	BootstrapConfigURL    string `toml:"bootstrap_config_url"`
	BootstrapSecret       string `toml:"bootstrap_secret"`
	BindAddr              string `toml:"bind_addr"`
	BootstrapHTTPTimeout  string `toml:"bootstrap_http_timeout"`
	MaxTotalPeers         int    `toml:"max_total_peers"`
	MaxRoomPeers          int    `toml:"max_room_peers"`
	RoomEndGraceSeconds   int    `toml:"room_end_grace_seconds"`
	EventWorkers          int    `toml:"event_workers"`
	EventQueueSize        int    `toml:"event_queue_size"`
	HTTPTimeoutSeconds    int    `toml:"http_timeout_seconds"`
	WSWriteTimeoutSeconds int    `toml:"ws_write_timeout_seconds"`
	WSPingIntervalSeconds int    `toml:"ws_ping_interval_seconds"`
	WSPongWaitSeconds     int    `toml:"ws_pong_wait_seconds"`
	WSReadLimitBytes      int    `toml:"ws_read_limit_bytes"`
	UDPPortMin            int    `toml:"udp_port_min"`
	UDPPortMax            int    `toml:"udp_port_max"`
}

// TOMLConfig represents the overall structure of config.toml
type TOMLConfig struct {
	MediaSFU MediaSFUConfig `toml:"media-sfu"`
}

// loadConfigFromTOML reads and parses the config.toml file
func loadConfigFromTOML(filePath string) (*MediaSFUConfig, error) {
	if filePath == "" {
		return &MediaSFUConfig{}, nil // Return empty config if no path provided
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg TOMLConfig
	if err := toml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg.MediaSFU, nil
}

type sfuServer struct {
	bindAddr        string
	internalAPIBase string
	internalSecret  string

	maxTotalPeers int
	maxRoomPeers  int
	roomEndGrace  time.Duration

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
	roomEnd map[string]*time.Timer

	upgrader websocket.Upgrader

	totalPeers            atomic.Int64
	rejectedConnections   atomic.Int64
	droppedInternalEvents atomic.Int64
}

func newServer(configPath string) (*sfuServer, error) {
	// Load config from TOML file if provided
	var tomlConfig *MediaSFUConfig
	if configPath != "" {
		cfg, err := loadConfigFromTOML(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config.toml: %w", err)
		}
		tomlConfig = cfg
	} else {
		tomlConfig = &MediaSFUConfig{}
	}

	// Helper to get config value, preferring TOML > env var > fallback
	getStringConfig := func(tomlVal, envKey, fallback string) string {
		if tomlVal != "" {
			return tomlVal
		}
		return envOrDefault(envKey, fallback)
	}

	getIntConfig := func(tomlVal int, envKey string, fallback int) int {
		if tomlVal > 0 {
			return tomlVal
		}
		envVal := envIntOrDefault(envKey, fallback)
		if envVal > 0 {
			return envVal
		}
		return fallback
	}

	getDurationConfig := func(tomlVal string, envKey string, fallback time.Duration) time.Duration {
		if tomlVal != "" {
			if d, err := time.ParseDuration(tomlVal); err == nil {
				return d
			}
		}
		return envDurationOrDefault(envKey, fallback)
	}

	// Determine bind address
	bindAddr := getStringConfig(tomlConfig.BindAddr, "RTC_BIND_ADDR", ":8787")

	// Determine resource limits and timeouts
	maxTotalPeers := getIntConfig(tomlConfig.MaxTotalPeers, "RTC_MAX_TOTAL_PEERS", 200)
	maxRoomPeers := getIntConfig(tomlConfig.MaxRoomPeers, "RTC_MAX_ROOM_PEERS", 60)
	roomEndGraceSeconds := getIntConfig(tomlConfig.RoomEndGraceSeconds, "RTC_ROOM_END_GRACE_SECONDS", 15)
	eventWorkers := getIntConfig(tomlConfig.EventWorkers, "RTC_EVENT_WORKERS", 4)
	eventQueueSize := getIntConfig(tomlConfig.EventQueueSize, "RTC_EVENT_QUEUE_SIZE", 4096)

	writeTimeout := getDurationConfig(
		func() string {
			if tomlConfig.WSWriteTimeoutSeconds > 0 {
				return fmt.Sprintf("%ds", tomlConfig.WSWriteTimeoutSeconds)
			}
			return ""
		}(),
		"RTC_WS_WRITE_TIMEOUT",
		4*time.Second,
	)
	pingInterval := getDurationConfig(
		func() string {
			if tomlConfig.WSPingIntervalSeconds > 0 {
				return fmt.Sprintf("%ds", tomlConfig.WSPingIntervalSeconds)
			}
			return ""
		}(),
		"RTC_WS_PING_INTERVAL",
		20*time.Second,
	)
	pongWait := getDurationConfig(
		func() string {
			if tomlConfig.WSPongWaitSeconds > 0 {
				return fmt.Sprintf("%ds", tomlConfig.WSPongWaitSeconds)
			}
			return ""
		}(),
		"RTC_WS_PONG_WAIT",
		45*time.Second,
	)

	readLimit := int64(1024 * 1024)
	if tomlConfig.WSReadLimitBytes > 0 {
		readLimit = int64(tomlConfig.WSReadLimitBytes)
	}

	httpTimeout := time.Duration(getIntConfig(tomlConfig.HTTPTimeoutSeconds, "RTC_HTTP_TIMEOUT_SECONDS", 5)) * time.Second

	server := &sfuServer{
		bindAddr:      bindAddr,
		maxTotalPeers: maxTotalPeers,
		maxRoomPeers:  maxRoomPeers,
		roomEndGrace:  time.Duration(roomEndGraceSeconds) * time.Second,
		readLimit:     readLimit,
		writeTimeout:  writeTimeout,
		pingInterval:  pingInterval,
		pongWait:      pongWait,
		eventWorkers:  eventWorkers,
		eventQueue:    make(chan internalEvent, eventQueueSize),
		httpClient:    &http.Client{Timeout: httpTimeout},
		rooms:         map[string]*room{},
		roomEnd:       map[string]*time.Timer{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		},
	}

	bootstrapURL := getStringConfig(
		tomlConfig.BootstrapConfigURL,
		"RTC_BOOTSTRAP_CONFIG_URL",
		"http://localhost:7575/api/internal/v1/voice/bootstrap-config",
	)
	bootstrapURL = strings.TrimRight(bootstrapURL, "/")

	bootstrapSecret := getStringConfig(tomlConfig.BootstrapSecret, "RTC_BOOTSTRAP_SECRET", "")
	bootstrapSecret = strings.TrimSpace(bootstrapSecret)
	if bootstrapSecret == "" {
		return nil, errors.New("RTC_BOOTSTRAP_SECRET is required (set in config.toml [media-sfu] section or RTC_BOOTSTRAP_SECRET env var)")
	}

	bootstrapHTTPTimeout := getDurationConfig(tomlConfig.BootstrapHTTPTimeout, "RTC_BOOTSTRAP_HTTP_TIMEOUT", 5*time.Second)

	bootstrapClient := &http.Client{Timeout: bootstrapHTTPTimeout}
	bootstrapCfg, err := fetchBootstrapConfig(
		bootstrapClient,
		bootstrapURL,
		bootstrapSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("bootstrap config fetch failed: %w", err)
	}

	if strings.TrimSpace(bootstrapCfg.InternalAPIBase) == "" {
		return nil, errors.New("bootstrap config missing internal_api_base")
	}
	if strings.TrimSpace(bootstrapCfg.InternalSecret) == "" {
		return nil, errors.New("bootstrap config missing internal_secret")
	}

	server.internalAPIBase = strings.TrimRight(bootstrapCfg.InternalAPIBase, "/")
	server.internalSecret = bootstrapCfg.InternalSecret

	if bootstrapCfg.MaxTotalPeers > 0 {
		server.maxTotalPeers = bootstrapCfg.MaxTotalPeers
	}
	if bootstrapCfg.MaxRoomPeers > 0 {
		server.maxRoomPeers = bootstrapCfg.MaxRoomPeers
	}
	if bootstrapCfg.RoomEndGraceSeconds > 0 {
		server.roomEndGrace = time.Duration(bootstrapCfg.RoomEndGraceSeconds) * time.Second
	}
	if bootstrapCfg.InternalEventWorkers > 0 {
		server.eventWorkers = bootstrapCfg.InternalEventWorkers
	}
	if bootstrapCfg.InternalEventQueueSize >= 32 {
		server.eventQueue = make(chan internalEvent, bootstrapCfg.InternalEventQueueSize)
	}
	if bootstrapCfg.InternalHTTPTimeoutSec > 0 {
		server.httpClient = &http.Client{
			Timeout: time.Duration(bootstrapCfg.InternalHTTPTimeoutSec) * time.Second,
		}
	}
	if bootstrapCfg.WSWriteTimeoutSec > 0 {
		server.writeTimeout = time.Duration(bootstrapCfg.WSWriteTimeoutSec) * time.Second
	}
	if bootstrapCfg.WSPongWaitSec > 0 {
		server.pongWait = time.Duration(bootstrapCfg.WSPongWaitSec) * time.Second
	}
	if bootstrapCfg.WSPingIntervalSec > 0 {
		server.pingInterval = time.Duration(bootstrapCfg.WSPingIntervalSec) * time.Second
	}
	if server.pingInterval >= server.pongWait {
		server.pingInterval = server.pongWait / 2
	}
	if bootstrapCfg.WSReadLimitBytes > 0 {
		server.readLimit = int64(bootstrapCfg.WSReadLimitBytes)
	}

	minUDPPort := bootstrapCfg.UDPPortMin
	maxUDPPort := bootstrapCfg.UDPPortMax
	if minUDPPort <= 0 {
		minUDPPort = 50000
	}
	if maxUDPPort <= 0 {
		maxUDPPort = 50199
	}

	settingEngine := webrtc.SettingEngine{}
	if minUDPPort > 0 && maxUDPPort >= minUDPPort && maxUDPPort <= 65535 {
		if err := settingEngine.SetEphemeralUDPPortRange(uint16(minUDPPort), uint16(maxUDPPort)); err != nil {
			log.Printf("failed setting UDP port range (%d-%d): %v", minUDPPort, maxUDPPort, err)
		}
	}

	server.iceServers = parseBootstrapIceServers(bootstrapCfg.IceServers)
	server.webrtcAPI = webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	return server, nil
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

func parseBootstrapIceServers(entries []bootstrapIceServer) []webrtc.ICEServer {
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		urls := make([]string, 0, 2)
		switch value := entry.URLs.(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				urls = append(urls, strings.TrimSpace(value))
			}
		case []any:
			for _, item := range value {
				if asString, ok := item.(string); ok && strings.TrimSpace(asString) != "" {
					urls = append(urls, strings.TrimSpace(asString))
				}
			}
		}

		if len(urls) == 0 {
			continue
		}

		server := webrtc.ICEServer{
			URLs: urls,
		}
		if strings.TrimSpace(entry.Username) != "" {
			server.Username = entry.Username
		}
		if strings.TrimSpace(entry.Credential) != "" {
			server.Credential = entry.Credential
		}
		servers = append(servers, server)
	}
	return servers
}

func signBootstrapPayload(secret string, timestamp int64, nonce string, body []byte) string {
	payload := []byte(fmt.Sprintf("%d.%s.", timestamp, nonce))
	payload = append(payload, body...)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func fetchBootstrapConfig(client *http.Client, endpoint string, secret string) (*sfuBootstrapConfig, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := time.Now().UTC().Unix()
	body, _ := json.Marshal(map[string]any{
		"service": "media-sfu",
		"nonce":   nonce,
	})

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pufferblow-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Pufferblow-Nonce", nonce)
	req.Header.Set("X-Pufferblow-Signature", signBootstrapPayload(secret, timestamp, nonce, body))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var decoded bootstrapConfigResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, err
	}

	return &decoded.Config, nil
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
		"room_end_grace_seconds":   int(s.roomEndGrace.Seconds()),
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

	var timer *time.Timer
	s.roomsMu.Lock()
	delete(s.rooms, r.SessionID)
	timer = s.roomEnd[r.SessionID]
	delete(s.roomEnd, r.SessionID)
	s.roomsMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

func (s *sfuServer) cancelRoomEndTimer(sessionID string) {
	var timer *time.Timer
	s.roomsMu.Lock()
	timer = s.roomEnd[sessionID]
	delete(s.roomEnd, sessionID)
	s.roomsMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

func (s *sfuServer) scheduleRoomEndGrace(r *room) {
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

	timer := time.AfterFunc(s.roomEndGrace, func() {
		if r.peerCount() > 0 {
			return
		}

		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "empty_grace_timeout",
		})
		s.deleteRoomIfEmpty(r)
	})

	s.roomsMu.Lock()
	s.roomEnd[r.SessionID] = timer
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
		s.scheduleRoomEndGrace(r)
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
	s.cancelRoomEndTimer(claims.SessionID)
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
	configPath := flag.String("config", "", "Path to config.toml file")
	flag.Parse()

	server, err := newServer(*configPath)
	if err != nil {
		log.Fatalf("failed to initialize media-sfu: %v", err)
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
		"media-sfu listening on %s (max_total_peers=%d max_room_peers=%d room_end_grace=%s workers=%d)",
		server.bindAddr,
		server.maxTotalPeers,
		server.maxRoomPeers,
		server.roomEndGrace,
		server.eventWorkers,
	)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("media-sfu server error: %v", err)
	}
}
