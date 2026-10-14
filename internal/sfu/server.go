// Package sfu is the Pufferblow media plane: a WebRTC selective
// forwarding unit that relays RTP between the peers of a voice session
// and defers every auth and session decision to the Pufferblow API.
package sfu

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lmittmann/tint"
	"github.com/pion/webrtc/v4"
)

// Version is reported by /healthz, /metrics and the startup log.
const Version = "0.2.0"

// ─────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────

type Server struct {
	bindAddr        string
	internalAPIBase string
	internalSecret  string
	metricsSecret   string // if set, /metrics requires X-Pufferblow-Signature

	// Multi-instance registry identity (see pufferblow's media_sfu_instances
	// table) — reported on every heartbeat, never overridden by bootstrap-config.
	instanceID         string
	region             string
	publicSignalingURL string
	heartbeatInterval  time.Duration

	maxTotalPeers int
	maxRoomPeers  int
	roomEndGrace  time.Duration

	readLimit    int64
	writeTimeout time.Duration
	pingInterval time.Duration
	pongWait     time.Duration

	eventWorkers int
	eventQueue   chan internalEvent

	httpClient   *http.Client
	webrtcAPI    *webrtc.API
	iceServers   []webrtc.ICEServer
	mediaQuality mediaQualityBootstrap

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

func New(configPath string) (*Server, error) {
	tomlConfig, err := loadConfigFromTOML(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config.toml: %w", err)
	}

	// ── helpers ──────────────────────────────────────
	// All configuration is read exclusively from the shared Pufferblow config.toml.
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
	replaceAttr := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			a.Key = "ts"
		}
		return a
	}
	isTTY := func(f *os.File) bool {
		fi, err := f.Stat()
		return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	}
	var handler slog.Handler
	if isTTY(os.Stdout) {
		handler = tint.NewHandler(os.Stdout, &tint.Options{
			Level:       slogLevel,
			TimeFormat:  time.DateTime,
			ReplaceAttr: replaceAttr,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:       slogLevel,
			ReplaceAttr: replaceAttr,
		})
	}
	logger := slog.New(handler)

	// ── core config ───────────────────────────────────
	bindAddr := str(tomlConfig.BindAddr, ":8787")
	maxTotalPeers := integer(tomlConfig.MaxTotalPeers, 1000)
	maxRoomPeers := integer(tomlConfig.MaxRoomPeers, 100)
	roomEndGrace := integer(tomlConfig.RoomEndGraceSeconds, 15)
	eventWorkers := integer(tomlConfig.EventWorkers, runtime.NumCPU()*2)
	eventQSize := integer(tomlConfig.EventQueueSize, 8192)

	writeTimeout := dur(durFromSec(tomlConfig.WSWriteTimeoutSeconds), 4*time.Second)
	pingInterval := dur(durFromSec(tomlConfig.WSPingIntervalSeconds), 20*time.Second)
	pongWait := dur(durFromSec(tomlConfig.WSPongWaitSeconds), 45*time.Second)
	if pingInterval >= pongWait {
		pingInterval = pongWait / 2
	}

	readLimit := int64(1024 * 1024)
	if tomlConfig.WSReadLimitBytes > 0 {
		readLimit = int64(tomlConfig.WSReadLimitBytes)
	}

	httpTimeout := time.Duration(integer(tomlConfig.HTTPTimeoutSeconds, 5)) * time.Second
	metricsSecret := str(tomlConfig.MetricsSecret, "")

	// ── instance registry identity ─────────────────────
	// instance_id has no safe default that stays stable across restarts
	// without operator input, but the registry degrades gracefully either
	// way: an unconfigured instance just registers under a fresh random id
	// each restart, which only matters for dashboards, not correctness.
	instanceID := str(tomlConfig.InstanceID, randomInstanceID())
	region := str(tomlConfig.Region, "default")
	publicSignalingURL := strings.TrimSpace(tomlConfig.PublicSignalingURL)
	heartbeatInterval := dur(
		durFromSec(tomlConfig.HeartbeatIntervalSeconds), 10*time.Second,
	)

	server := &Server{
		bindAddr:           bindAddr,
		metricsSecret:      metricsSecret,
		instanceID:         instanceID,
		region:             region,
		publicSignalingURL: publicSignalingURL,
		heartbeatInterval:  heartbeatInterval,
		maxTotalPeers:      maxTotalPeers,
		maxRoomPeers:       maxRoomPeers,
		roomEndGrace:       time.Duration(roomEndGrace) * time.Second,
		readLimit:          readLimit,
		writeTimeout:       writeTimeout,
		pingInterval:       pingInterval,
		pongWait:           pongWait,
		eventWorkers:       eventWorkers,
		eventQueue:         make(chan internalEvent, eventQSize),
		httpClient:         &http.Client{Timeout: httpTimeout},
		rooms:              map[string]*room{},
		roomEnd:            map[string]*time.Timer{},
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
	server.mediaQuality = bootstrapCfg.MediaQuality
	server.webrtcAPI = webrtc.NewAPI(webrtc.WithSettingEngine(se))

	if iceSummary := summarizeICEServersForLog(server.iceServers); len(iceSummary) > 0 {
		// One info line per ICE server so operators can spot mis-configured
		// TURN credentials at boot. Credentials themselves are never logged.
		for i, line := range iceSummary {
			logger.Info("ICE server configured", "index", i, "spec", line)
		}
	} else {
		logger.Warn("No ICE servers configured — peers behind strict NAT will fail to connect")
	}

	logger.Info("pufferblow media-sfu initialised",
		"version", Version,
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
		"default_quality_profile", server.mediaQuality.DefaultProfile,
		"audio_bitrate_balanced_kbps", server.mediaQuality.Audio.Profiles["balanced"].BitrateKbps,
		"video_bitrate_balanced_kbps", server.mediaQuality.Video.Profiles["balanced"].BitrateKbps,
		"log_level", logLevel,
		"metrics_auth", metricsSecret != "",
	)

	return server, nil
}

// ─────────────────────────────────────────────
// Serve
// ─────────────────────────────────────────────

// Serve starts the internal event workers and the registry heartbeat, then
// serves HTTP on the configured bind address until ctx is cancelled, at
// which point it disconnects every peer, flushes pending lifecycle events
// and stops the listener. It returns an error only if the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	s.startEventWorkers()
	s.startHeartbeatLoop()

	httpServer := &http.Server{
		Addr:              s.bindAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	listenErr := make(chan error, 1)
	go func() {
		s.log.Info("media-sfu listening",
			"addr", s.bindAddr,
			"version", Version,
			"max_total_peers", s.maxTotalPeers,
			"max_room_peers", s.maxRoomPeers,
		)
		listenErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-listenErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server error: %w", err)
	case <-ctx.Done():
	}
	s.log.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.shutdown(shutdownCtx)

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		s.log.Error("http server shutdown error", "err", err)
	}

	s.log.Info("media-sfu stopped cleanly",
		"total_joins", s.totalJoins.Load(),
		"total_leaves", s.totalLeaves.Load(),
		"rejected_connections", s.rejectedConnections.Load(),
		"dropped_internal_events", s.droppedInternalEvents.Load(),
		"tracks_fanned", s.tracksFanned.Load(),
	)
	return nil
}

// ─────────────────────────────────────────────
// Peer slot management
// ─────────────────────────────────────────────

// reservePeerSlot atomically increments the global peer counter if capacity
// allows. Returns false if the server is at capacity.
func (s *Server) reservePeerSlot() bool {
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

func (s *Server) releasePeerSlot() {
	s.totalPeers.Add(-1)
}
