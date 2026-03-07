package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

// ─────────────────────────────────────────────
// Version
// ─────────────────────────────────────────────

const version = "0.2.0"

// ─────────────────────────────────────────────
// Token / Bootstrap types
// ─────────────────────────────────────────────

// joinClaims are the verified fields extracted from a one-time join token
// issued by the Pufferblow backend. Sub is the user UUID, Scope encodes
// what the peer is allowed to do in this session.
//
// Scope values (space-separated, any combination):
//   send_audio   – peer may publish microphone audio
//   send_video   – peer may publish camera / screenshare video
//   recv         – peer may subscribe to other participants' tracks
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
// Internal event (SFU → Pufferblow backend)
// ─────────────────────────────────────────────

type internalEvent struct {
	EventType string
	Payload   map[string]any
}

// ─────────────────────────────────────────────
// Participant snapshot (sent to clients)
// ─────────────────────────────────────────────

type participantSnapshot struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username,omitempty"`
	IsMuted     bool   `json:"is_muted"`
	IsDeafened  bool   `json:"is_deafened"`
	IsSpeaking  bool   `json:"is_speaking"`
	Scope       string `json:"scope"`
	ConnectedAt string `json:"connected_at"`
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

	// State fields — guarded by stateMu, NOT the room lock.
	// Separating this mutex avoids holding the room lock during snapshot
	// iteration while audio_state messages are being processed concurrently.
	stateMu    sync.RWMutex
	IsMuted    bool
	IsDeafened bool
	IsSpeaking bool
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
		UserID:      p.UserID,
		Username:    p.Username,
		IsMuted:     p.IsMuted,
		IsDeafened:  p.IsDeafened,
		IsSpeaking:  p.IsSpeaking,
		Scope:       p.Scope,
		ConnectedAt: p.ConnectedAt.UTC().Format(time.RFC3339),
	}
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

// ─────────────────────────────────────────────
// Room
// ─────────────────────────────────────────────

type room struct {
	SessionID string
	ChannelID string

	Mu     sync.RWMutex
	Peers  map[string]*peer
	Tracks map[string]*webrtc.TrackLocalStaticRTP
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
// Metrics
// ─────────────────────────────────────────────

type roomMetric struct {
	SessionID string `json:"session_id"`
	ChannelID string `json:"channel_id"`
	Peers     int    `json:"peers"`
}

// ─────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────

type MediaSFUConfig struct {
	BootstrapConfigURL    string `toml:"bootstrap_config_url"`
	BootstrapSecret       string `toml:"bootstrap_secret"`
	BindAddr              string `toml:"bind_addr"`
	BootstrapHTTPTimeout  string `toml:"bootstrap_http_timeout"`
	BootstrapMaxRetries   int    `toml:"bootstrap_max_retries"`
	BootstrapRetryDelay   string `toml:"bootstrap_retry_delay"`
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
	LogLevel              string `toml:"log_level"`
	MetricsSecret         string `toml:"metrics_secret"`
}

type TOMLConfig struct {
	MediaSFU MediaSFUConfig `toml:"media-sfu"`
}

func loadConfigFromTOML(filePath string) (*MediaSFUConfig, error) {
	if filePath == "" {
		return &MediaSFUConfig{}, nil
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

// ─────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────

type sfuServer struct {
	bindAddr        string
	internalAPIBase string
	internalSecret  string
	metricsSecret   string // if set, /metrics requires X-Pufferblow-Signature

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

	// Counters
	totalPeers            atomic.Int64
	totalRooms            atomic.Int64
	totalJoins            atomic.Int64
	totalLeaves           atomic.Int64
	rejectedConnections   atomic.Int64
	droppedInternalEvents atomic.Int64
	tracksFanned          atomic.Int64

	log *slog.Logger
}

// ─────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────

func newServer(configPath string) (*sfuServer, error) {
	tomlConfig, err := loadConfigFromTOML(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config.toml: %w", err)
	}

	// ── helpers ──────────────────────────────────────
	// All configuration is read exclusively from config.toml.
	// If a value is absent or zero, the hardcoded default is used.
	// Environment variables are intentionally not consulted.
	str := func(tomlVal, fallback string) string {
		if strings.TrimSpace(tomlVal) != "" {
			return tomlVal
		}
		return fallback
	}
	integer := func(tomlVal, fallback int) int {
		if tomlVal > 0 {
			return tomlVal
		}
		return fallback
	}
	dur := func(tomlVal string, fallback time.Duration) time.Duration {
		if strings.TrimSpace(tomlVal) != "" {
			if d, parsedErr := time.ParseDuration(tomlVal); parsedErr == nil {
				return d
			}
		}
		return fallback
	}
	durFromSec := func(seconds int) string {
		if seconds > 0 {
			return fmt.Sprintf("%ds", seconds)
		}
		return ""
	}

	// ── logging ───────────────────────────────────────
	logLevel := str(tomlConfig.LogLevel, "info")
	var slogLevel slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Rename "time" → "ts" to match Pufferblow backend log format
			if a.Key == slog.TimeKey {
				a.Key = "ts"
			}
			return a
		},
	}))

	// ── core config ───────────────────────────────────
	bindAddr      := str(tomlConfig.BindAddr, ":8787")
	maxTotalPeers := integer(tomlConfig.MaxTotalPeers, 1000)
	maxRoomPeers  := integer(tomlConfig.MaxRoomPeers, 100)
	roomEndGrace  := integer(tomlConfig.RoomEndGraceSeconds, 15)
	eventWorkers  := integer(tomlConfig.EventWorkers, runtime.NumCPU()*2)
	eventQSize    := integer(tomlConfig.EventQueueSize, 8192)

	writeTimeout := dur(durFromSec(tomlConfig.WSWriteTimeoutSeconds), 4*time.Second)
	pingInterval := dur(durFromSec(tomlConfig.WSPingIntervalSeconds), 20*time.Second)
	pongWait     := dur(durFromSec(tomlConfig.WSPongWaitSeconds), 45*time.Second)
	if pingInterval >= pongWait {
		pingInterval = pongWait / 2
	}

	readLimit := int64(1024 * 1024)
	if tomlConfig.WSReadLimitBytes > 0 {
		readLimit = int64(tomlConfig.WSReadLimitBytes)
	}

	httpTimeout := time.Duration(integer(tomlConfig.HTTPTimeoutSeconds, 5)) * time.Second
	metricsSecret := str(tomlConfig.MetricsSecret, "")

	server := &sfuServer{
		bindAddr:      bindAddr,
		metricsSecret: metricsSecret,
		maxTotalPeers: maxTotalPeers,
		maxRoomPeers:  maxRoomPeers,
		roomEndGrace:  time.Duration(roomEndGrace) * time.Second,
		readLimit:     readLimit,
		writeTimeout:  writeTimeout,
		pingInterval:  pingInterval,
		pongWait:      pongWait,
		eventWorkers:  eventWorkers,
		eventQueue:    make(chan internalEvent, eventQSize),
		httpClient:    &http.Client{Timeout: httpTimeout},
		rooms:         map[string]*room{},
		roomEnd:       map[string]*time.Timer{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
			CheckOrigin:     func(_ *http.Request) bool { return true },
		},
		log: logger,
	}

	// ── bootstrap ─────────────────────────────────────
	bootstrapURL := str(tomlConfig.BootstrapConfigURL,
		"http://localhost:7575/api/internal/v1/voice/bootstrap-config")
	bootstrapURL = strings.TrimRight(bootstrapURL, "/")

	bootstrapSecret := strings.TrimSpace(str(tomlConfig.BootstrapSecret, ""))
	if bootstrapSecret == "" {
		return nil, errors.New("bootstrap_secret is required in config.toml [media-sfu]")
	}

	bootstrapTimeout := dur(tomlConfig.BootstrapHTTPTimeout, 5*time.Second)
	bootstrapMaxRetries := integer(tomlConfig.BootstrapMaxRetries, 10)
	bootstrapRetryDelay := dur(tomlConfig.BootstrapRetryDelay, 3*time.Second)
	bootstrapClient := &http.Client{Timeout: bootstrapTimeout}

	bootstrapCfg, err := fetchBootstrapConfigWithRetry(
		bootstrapClient, bootstrapURL, bootstrapSecret,
		bootstrapMaxRetries, bootstrapRetryDelay, logger,
	)
	if err != nil {
		return nil, fmt.Errorf("bootstrap config fetch failed after retries: %w", err)
	}

	if strings.TrimSpace(bootstrapCfg.InternalAPIBase) == "" {
		return nil, errors.New("bootstrap config missing internal_api_base")
	}
	if strings.TrimSpace(bootstrapCfg.InternalSecret) == "" {
		return nil, errors.New("bootstrap config missing internal_secret")
	}

	server.internalAPIBase = strings.TrimRight(bootstrapCfg.InternalAPIBase, "/")
	server.internalSecret = bootstrapCfg.InternalSecret

	// Bootstrap config overrides local config where set
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

	// ── WebRTC engine ─────────────────────────────────
	minUDP := bootstrapCfg.UDPPortMin
	maxUDP := bootstrapCfg.UDPPortMax
	if minUDP <= 0 {
		minUDP = 50000
	}
	if maxUDP <= 0 {
		// For 1000 concurrent peers each needing 1 UDP port, give headroom
		maxUDP = 51999
	}

	se := webrtc.SettingEngine{}
	if minUDP > 0 && maxUDP >= minUDP && maxUDP <= 65535 {
		if rangeErr := se.SetEphemeralUDPPortRange(uint16(minUDP), uint16(maxUDP)); rangeErr != nil {
			logger.Warn("failed to set UDP port range",
				"min", minUDP, "max", maxUDP, "err", rangeErr)
		} else {
			logger.Info("UDP port range configured", "min", minUDP, "max", maxUDP)
		}
	}

	server.iceServers = parseBootstrapIceServers(bootstrapCfg.IceServers)
	server.webrtcAPI = webrtc.NewAPI(webrtc.WithSettingEngine(se))

	logger.Info("pufferblow media-sfu initialised",
		"version", version,
		"bind_addr", bindAddr,
		"max_total_peers", server.maxTotalPeers,
		"max_room_peers", server.maxRoomPeers,
		"room_end_grace", server.roomEndGrace,
		"event_workers", server.eventWorkers,
		"event_queue_cap", cap(server.eventQueue),
		"ping_interval", server.pingInterval,
		"pong_wait", server.pongWait,
		"write_timeout", server.writeTimeout,
		"read_limit_bytes", server.readLimit,
		"ice_servers", len(server.iceServers),
		"log_level", logLevel,
		"metrics_auth", metricsSecret != "",
	)

	return server, nil
}

// ─────────────────────────────────────────────
// Bootstrap fetch with retry
// ─────────────────────────────────────────────

func fetchBootstrapConfigWithRetry(
	client *http.Client,
	endpoint, secret string,
	maxRetries int,
	retryDelay time.Duration,
	logger *slog.Logger,
) (*sfuBootstrapConfig, error) {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		cfg, err := fetchBootstrapConfig(client, endpoint, secret)
		if err == nil {
			if attempt > 1 {
				logger.Info("bootstrap config fetch succeeded", "attempt", attempt)
			}
			return cfg, nil
		}
		lastErr = err
		logger.Warn("bootstrap config fetch failed, will retry",
			"attempt", attempt,
			"max_retries", maxRetries,
			"retry_delay", retryDelay,
			"err", err,
		)
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}
	return nil, lastErr
}

func signBootstrapPayload(secret string, timestamp int64, nonce string, body []byte) string {
	payload := []byte(fmt.Sprintf("%d.%s.", timestamp, nonce))
	payload = append(payload, body...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func fetchBootstrapConfig(client *http.Client, endpoint, secret string) (*sfuBootstrapConfig, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := time.Now().UTC().Unix()
	body, _ := json.Marshal(map[string]any{"service": "media-sfu", "nonce": nonce})

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

// ─────────────────────────────────────────────
// HTTP handlers
// ─────────────────────────────────────────────

func (s *sfuServer) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     version,
		"total_peers": s.totalPeers.Load(),
		"active_rooms": func() int {
			s.roomsMu.RLock()
			defer s.roomsMu.RUnlock()
			return len(s.rooms)
		}(),
	})
	s.log.Debug("healthz", "remote_addr", r.RemoteAddr)
}

func (s *sfuServer) metrics(w http.ResponseWriter, r *http.Request) {
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
		"version":                  version,
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
		"rooms":                    roomMetrics,
	})
}

// ─────────────────────────────────────────────
// Room lifecycle
// ─────────────────────────────────────────────

func (s *sfuServer) getOrCreateRoom(sessionID, channelID string) (*room, bool) {
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
		Tracks:    map[string]*webrtc.TrackLocalStaticRTP{},
	}
	s.rooms[sessionID] = r
	s.totalRooms.Add(1)
	return r, true // created
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
	if t := s.roomEnd[r.SessionID]; t != nil {
		t.Stop()
	}
	delete(s.roomEnd, r.SessionID)
	s.roomsMu.Unlock()

	s.log.Info("room deleted", "session_id", r.SessionID, "channel_id", r.ChannelID)
}

func (s *sfuServer) cancelRoomEndTimer(sessionID string) {
	s.roomsMu.Lock()
	if t := s.roomEnd[sessionID]; t != nil {
		t.Stop()
	}
	delete(s.roomEnd, sessionID)
	s.roomsMu.Unlock()
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
// Peer slot management
// ─────────────────────────────────────────────

// reservePeerSlot atomically increments the global peer counter if capacity
// allows. Returns false if the server is at capacity.
func (s *sfuServer) reservePeerSlot() bool {
	if s.maxTotalPeers <= 0 {
		s.totalPeers.Add(1)
		return true
	}
	for {
		cur := s.totalPeers.Load()
		if int(cur) >= s.maxTotalPeers {
			return false
		}
		if s.totalPeers.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (s *sfuServer) releasePeerSlot() {
	s.totalPeers.Add(-1)
}

// ─────────────────────────────────────────────
// Internal event workers
// ─────────────────────────────────────────────

func (s *sfuServer) startEventWorkers() {
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

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *sfuServer) postInternalEvent(event internalEvent) {
	body, _ := json.Marshal(map[string]any{
		"event_type": event.EventType,
		"payload":    event.Payload,
	})
	endpoint := s.internalAPIBase + "/events"

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		s.log.Error("internal event: failed to build request",
			"event_type", event.EventType, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pufferblow-Signature", signPayload(s.internalSecret, body))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.log.Error("internal event: POST failed",
			"event_type", event.EventType, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		s.log.Warn("internal event: backend rejected event",
			"event_type", event.EventType,
			"status", resp.StatusCode,
			"body", string(data),
		)
		return
	}
	s.log.Debug("internal event: delivered",
		"event_type", event.EventType,
		"status", resp.StatusCode,
	)
}

func (s *sfuServer) emitInternalEvent(eventType string, payload map[string]any) {
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

// ─────────────────────────────────────────────
// Token validation
// ─────────────────────────────────────────────

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
			return nil, fmt.Errorf("join token consume failed: status %d", resp.StatusCode)
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

// ─────────────────────────────────────────────
// Track fanout
// ─────────────────────────────────────────────

func (s *sfuServer) addTrackToPeer(target *peer, track *webrtc.TrackLocalStaticRTP) error {
	sender, err := target.PC.AddTrack(track)
	if err != nil {
		return err
	}
	// Drain RTCP — required or the sender will stall.
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, readErr := sender.Read(buf); readErr != nil {
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
	return target.send(signalMessage{
		Type:      "offer",
		SessionID: target.SessionID,
		Offer:     &offer,
	})
}

// handleRemoteTrack proxies RTP from a source peer to all other peers in the room.
// Each fanout runs in a separate goroutine to avoid one slow peer blocking others.
func (s *sfuServer) handleRemoteTrack(r *room, srcPeer *peer, remoteTrack *webrtc.TrackRemote) {
	trackKey := fmt.Sprintf("%s:%s", srcPeer.UserID, remoteTrack.ID())

	s.log.Info("remote track started",
		"session_id", r.SessionID,
		"user_id", srcPeer.UserID,
		"track_id", remoteTrack.ID(),
		"codec", remoteTrack.Codec().MimeType,
		"kind", remoteTrack.Kind().String(),
	)

	localTrack, err := webrtc.NewTrackLocalStaticRTP(
		remoteTrack.Codec().RTPCodecCapability,
		fmt.Sprintf("%s-%s", srcPeer.UserID, remoteTrack.ID()),
		"pufferblow",
	)
	if err != nil {
		s.log.Error("failed to create local RTP track",
			"session_id", r.SessionID, "user_id", srcPeer.UserID, "err", err)
		return
	}

	// Collect current peers and register the track — all under one lock acquisition.
	r.Mu.Lock()
	r.Tracks[trackKey] = localTrack
	targets := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		if p.UserID != srcPeer.UserID {
			targets = append(targets, p)
		}
	}
	r.Mu.Unlock()

	// Fan out to existing peers in parallel — one goroutine per target.
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(t *peer) {
			defer wg.Done()
			if fanErr := s.addTrackToPeer(t, localTrack); fanErr != nil {
				s.log.Warn("track fanout failed",
					"track_key", trackKey,
					"target_user_id", t.UserID,
					"err", fanErr,
				)
				return
			}
			s.tracksFanned.Add(1)
			s.log.Debug("track fanned",
				"track_key", trackKey,
				"target_user_id", t.UserID,
			)
		}(target)
	}
	wg.Wait()

	// Forward RTP packets from the remote source to the local forwarder.
	for {
		pkt, _, readErr := remoteTrack.ReadRTP()
		if readErr != nil {
			break
		}
		if writeErr := localTrack.WriteRTP(pkt); writeErr != nil {
			break
		}
	}

	r.Mu.Lock()
	delete(r.Tracks, trackKey)
	r.Mu.Unlock()

	s.log.Info("remote track ended",
		"session_id", r.SessionID,
		"user_id", srcPeer.UserID,
		"track_id", remoteTrack.ID(),
	)
}

// ─────────────────────────────────────────────
// Peer removal
// ─────────────────────────────────────────────

func (s *sfuServer) removePeer(r *room, p *peer, reason string) {
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

func (s *sfuServer) broadcastRoom(r *room, msg signalMessage, exceptUserID string) {
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

// ─────────────────────────────────────────────
// WebSocket handler
// ─────────────────────────────────────────────

func (s *sfuServer) handleWS(w http.ResponseWriter, r *http.Request) {
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
	var existingTracks []*webrtc.TrackLocalStaticRTP
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
	existingTracks = make([]*webrtc.TrackLocalStaticRTP, 0, len(roomObj.Tracks))
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

	// Fan existing tracks to the new peer in parallel.
	if len(existingTracks) > 0 {
		var wg sync.WaitGroup
		for _, t := range existingTracks {
			wg.Add(1)
			go func(track *webrtc.TrackLocalStaticRTP) {
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

		case "ping":
			_ = peerObj.send(signalMessage{Type: "pong", SessionID: roomObj.SessionID})

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

// ─────────────────────────────────────────────
// Graceful shutdown
// ─────────────────────────────────────────────

func (s *sfuServer) shutdown(ctx context.Context) {
	s.log.Info("graceful shutdown initiated")

	// Collect all peers across all rooms.
	s.roomsMu.RLock()
	rooms := make([]*room, 0, len(s.rooms))
	for _, r := range s.rooms {
		rooms = append(rooms, r)
	}
	s.roomsMu.RUnlock()

	// Send close frames and close peer connections.
	for _, r := range rooms {
		r.Mu.RLock()
		peers := make([]*peer, 0, len(r.Peers))
		for _, p := range r.Peers {
			peers = append(peers, p)
		}
		r.Mu.RUnlock()

		for _, p := range peers {
			s.log.Debug("shutdown: closing peer",
				"user_id", p.UserID, "session_id", r.SessionID)
			_ = p.WS.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down"),
				time.Now().Add(2*time.Second),
			)
			_ = p.WS.Close()
			_ = p.PC.Close()

			s.emitInternalEvent("participant_left", map[string]any{
				"session_id": r.SessionID,
				"channel_id": r.ChannelID,
				"user_id":    p.UserID,
				"reason":     "server_shutdown",
			})
		}

		s.emitInternalEvent("session_ended", map[string]any{
			"session_id": r.SessionID,
			"channel_id": r.ChannelID,
			"reason":     "server_shutdown",
		})
	}

	// Drain the event queue — give workers up to 10 seconds to flush.
	close(s.eventQueue)
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-drainCtx.Done():
			s.log.Warn("shutdown: event queue drain timed out",
				"remaining", len(s.eventQueue))
			return
		case <-ticker.C:
			if len(s.eventQueue) == 0 {
				s.log.Info("shutdown: event queue drained")
				return
			}
		}
	}
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseBootstrapIceServers(entries []bootstrapIceServer) []webrtc.ICEServer {
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		var urls []string
		switch v := entry.URLs.(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				urls = append(urls, s)
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					urls = append(urls, strings.TrimSpace(s))
				}
			}
		}
		if len(urls) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: urls}
		if strings.TrimSpace(entry.Username) != "" {
			srv.Username = entry.Username
		}
		if strings.TrimSpace(entry.Credential) != "" {
			srv.Credential = entry.Credential
		}
		servers = append(servers, srv)
	}
	return servers
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func main() {
	configPath := flag.String("config", "", "Path to config.toml file")
	flag.Parse()

	server, err := newServer(*configPath)
	if err != nil {
		slog.Error("failed to initialise media-sfu", "err", err)
		os.Exit(1)
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

	// ── Signal handling + graceful shutdown ───────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		server.log.Info("media-sfu listening",
			"addr", server.bindAddr,
			"version", version,
			"max_total_peers", server.maxTotalPeers,
			"max_room_peers", server.maxRoomPeers,
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.log.Error("http server error", "err", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	server.log.Info("shutdown signal received", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server.shutdown(shutdownCtx)

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		server.log.Error("http server shutdown error", "err", err)
	}

	server.log.Info("media-sfu stopped cleanly",
		"total_joins", server.totalJoins.Load(),
		"total_leaves", server.totalLeaves.Load(),
		"rejected_connections", server.rejectedConnections.Load(),
		"dropped_internal_events", server.droppedInternalEvents.Load(),
		"tracks_fanned", server.tracksFanned.Load(),
	)
}