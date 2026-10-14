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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
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

// New builds a server from the shared config.toml and the Pufferblow API's
// bootstrap config, which it fetches (with retries) before returning.
//
// Precedence, highest first: bootstrap-config values, local [media-sfu]
// values, hardcoded defaults. Environment variables are intentionally not
// consulted.
func New(configPath string) (*Server, error) {
	cfg, err := loadConfigFromTOML(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config.toml: %w", err)
	}

	logLevel := orString(cfg.LogLevel, "info")
	logger := newLogger(logLevel)
	server := newFromLocalConfig(cfg, logger)

	bootstrapCfg, err := fetchBootstrap(cfg, logger)
	if err != nil {
		return nil, err
	}
	server.applyBootstrap(bootstrapCfg)

	server.logStartup(logLevel)
	return server, nil
}

// newFromLocalConfig builds a server from local config and defaults alone;
// New then layers the bootstrap config on top.
func newFromLocalConfig(cfg *MediaSFUConfig, logger *slog.Logger) *Server {
	pingInterval := secondsOr(cfg.WSPingIntervalSeconds, 20*time.Second)
	pongWait := secondsOr(cfg.WSPongWaitSeconds, 45*time.Second)
	if pingInterval >= pongWait {
		pingInterval = pongWait / 2
	}

	readLimit := int64(1024 * 1024)
	if cfg.WSReadLimitBytes > 0 {
		readLimit = int64(cfg.WSReadLimitBytes)
	}

	return &Server{
		bindAddr:      orString(cfg.BindAddr, ":8787"),
		metricsSecret: orString(cfg.MetricsSecret, ""),

		// instance_id has no safe default that stays stable across restarts
		// without operator input, but the registry degrades gracefully either
		// way: an unconfigured instance just registers under a fresh random id
		// each restart, which only matters for dashboards, not correctness.
		instanceID:         orString(cfg.InstanceID, randomInstanceID()),
		region:             orString(cfg.Region, "default"),
		publicSignalingURL: strings.TrimSpace(cfg.PublicSignalingURL),
		heartbeatInterval:  secondsOr(cfg.HeartbeatIntervalSeconds, 10*time.Second),

		maxTotalPeers: orInt(cfg.MaxTotalPeers, 1000),
		maxRoomPeers:  orInt(cfg.MaxRoomPeers, 100),
		roomEndGrace:  time.Duration(orInt(cfg.RoomEndGraceSeconds, 15)) * time.Second,

		readLimit:    readLimit,
		writeTimeout: secondsOr(cfg.WSWriteTimeoutSeconds, 4*time.Second),
		pingInterval: pingInterval,
		pongWait:     pongWait,

		eventWorkers: orInt(cfg.EventWorkers, runtime.NumCPU()*2),
		eventQueue:   make(chan internalEvent, orInt(cfg.EventQueueSize, 8192)),
		httpClient:   &http.Client{Timeout: time.Duration(orInt(cfg.HTTPTimeoutSeconds, 5)) * time.Second},

		rooms:   map[string]*room{},
		roomEnd: map[string]*time.Timer{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
			CheckOrigin:     func(_ *http.Request) bool { return true },
		},
		log: logger,
	}
}

// newWebRTCAPI builds the pion API, pinning ICE to the given UDP port
// range so operators can open exactly that range in their firewall.
func newWebRTCAPI(minUDP, maxUDP int, logger *slog.Logger) *webrtc.API {
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
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func (s *Server) logStartup(logLevel string) {
	if iceSummary := summarizeICEServersForLog(s.iceServers); len(iceSummary) > 0 {
		// One info line per ICE server so operators can spot mis-configured
		// TURN credentials at boot. Credentials themselves are never logged.
		for i, line := range iceSummary {
			s.log.Info("ICE server configured", "index", i, "spec", line)
		}
	} else {
		s.log.Warn("No ICE servers configured — peers behind strict NAT will fail to connect")
	}

	s.log.Info("pufferblow media-sfu initialised",
		"version", Version,
		"bind_addr", s.bindAddr,
		"max_total_peers", s.maxTotalPeers,
		"max_room_peers", s.maxRoomPeers,
		"room_end_grace", s.roomEndGrace,
		"event_workers", s.eventWorkers,
		"event_queue_cap", cap(s.eventQueue),
		"ping_interval", s.pingInterval,
		"pong_wait", s.pongWait,
		"write_timeout", s.writeTimeout,
		"read_limit_bytes", s.readLimit,
		"ice_servers", len(s.iceServers),
		"default_quality_profile", s.mediaQuality.DefaultProfile,
		"audio_bitrate_balanced_kbps", s.mediaQuality.Audio.Profiles["balanced"].BitrateKbps,
		"video_bitrate_balanced_kbps", s.mediaQuality.Video.Profiles["balanced"].BitrateKbps,
		"log_level", logLevel,
		"metrics_auth", s.metricsSecret != "",
	)
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
