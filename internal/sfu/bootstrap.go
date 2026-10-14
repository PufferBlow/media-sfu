package sfu

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type bootstrapIceServer struct {
	URLs       any    `json:"urls"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

type profileBitrate struct {
	BitrateKbps int `json:"bitrate_kbps"`
}

type videoProfile struct {
	BitrateKbps int `json:"bitrate_kbps"`
	Width       int `json:"width"`
	Height      int `json:"height"`
	FPS         int `json:"fps"`
}

type audioQualityBootstrap struct {
	SampleRateHz  int                       `json:"sample_rate_hz"`
	Channels      int                       `json:"channels"`
	StereoEnabled bool                      `json:"stereo_enabled"`
	DTXEnabled    bool                      `json:"dtx_enabled"`
	FECEnabled    bool                      `json:"fec_enabled"`
	Profiles      map[string]profileBitrate `json:"profiles"`
}

type videoQualityBootstrap struct {
	Profiles map[string]videoProfile `json:"profiles"`
}

type mediaQualityBootstrap struct {
	DefaultProfile string                `json:"default_profile"`
	Audio          audioQualityBootstrap `json:"audio"`
	Video          videoQualityBootstrap `json:"video"`
}

type sfuBootstrapConfig struct {
	InternalAPIBase        string                `json:"internal_api_base"`
	InternalSecret         string                `json:"internal_secret"`
	MaxTotalPeers          int                   `json:"max_total_peers"`
	MaxRoomPeers           int                   `json:"max_room_peers"`
	RoomEndGraceSeconds    int                   `json:"room_end_grace_seconds"`
	InternalEventWorkers   int                   `json:"internal_event_workers"`
	InternalEventQueueSize int                   `json:"internal_event_queue_size"`
	InternalHTTPTimeoutSec int                   `json:"internal_http_timeout_seconds"`
	WSWriteTimeoutSec      int                   `json:"ws_write_timeout_seconds"`
	WSPingIntervalSec      int                   `json:"ws_ping_interval_seconds"`
	WSPongWaitSec          int                   `json:"ws_pong_wait_seconds"`
	WSReadLimitBytes       int                   `json:"ws_read_limit_bytes"`
	UDPPortMin             int                   `json:"udp_port_min"`
	UDPPortMax             int                   `json:"udp_port_max"`
	IceServers             []bootstrapIceServer  `json:"ice_servers"`
	MediaQuality           mediaQualityBootstrap `json:"media_quality"`
}

type bootstrapConfigResponse struct {
	StatusCode int                `json:"status_code"`
	Config     sfuBootstrapConfig `json:"config"`
	Detail     string             `json:"detail"`
}

// ─────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────

// fetchBootstrap fetches the bootstrap config the local [media-sfu] table
// points at, retrying while the Pufferblow API comes up, and checks it
// carries the credentials every later internal call needs.
func fetchBootstrap(cfg *MediaSFUConfig, logger *slog.Logger) (*sfuBootstrapConfig, error) {
	bootstrapURL := orString(cfg.BootstrapConfigURL,
		"http://localhost:7575/api/internal/v1/voice/bootstrap-config")
	bootstrapURL = strings.TrimRight(bootstrapURL, "/")

	bootstrapSecret := strings.TrimSpace(cfg.BootstrapSecret)
	if bootstrapSecret == "" {
		return nil, errors.New("bootstrap_secret is required in config.toml [media-sfu]")
	}

	client := &http.Client{Timeout: orDuration(cfg.BootstrapHTTPTimeout, 5*time.Second)}
	bootstrapCfg, err := fetchBootstrapConfigWithRetry(
		client, bootstrapURL, bootstrapSecret,
		orInt(cfg.BootstrapMaxRetries, 10),
		orDuration(cfg.BootstrapRetryDelay, 3*time.Second),
		logger,
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
	return bootstrapCfg, nil
}

// applyBootstrap takes the internal API credentials from the bootstrap
// config, lets its operational values override local config where set,
// and builds the WebRTC engine from it.
func (s *Server) applyBootstrap(cfg *sfuBootstrapConfig) {
	s.internalAPIBase = strings.TrimRight(cfg.InternalAPIBase, "/")
	s.internalSecret = cfg.InternalSecret

	if cfg.MaxTotalPeers > 0 {
		s.maxTotalPeers = cfg.MaxTotalPeers
	}
	if cfg.MaxRoomPeers > 0 {
		s.maxRoomPeers = cfg.MaxRoomPeers
	}
	if cfg.RoomEndGraceSeconds > 0 {
		s.roomEndGrace = time.Duration(cfg.RoomEndGraceSeconds) * time.Second
	}
	if cfg.InternalEventWorkers > 0 {
		s.eventWorkers = cfg.InternalEventWorkers
	}
	if cfg.InternalEventQueueSize >= 32 {
		s.eventQueue = make(chan internalEvent, cfg.InternalEventQueueSize)
	}
	if cfg.InternalHTTPTimeoutSec > 0 {
		s.httpClient = &http.Client{
			Timeout: time.Duration(cfg.InternalHTTPTimeoutSec) * time.Second,
		}
	}
	if cfg.WSWriteTimeoutSec > 0 {
		s.writeTimeout = time.Duration(cfg.WSWriteTimeoutSec) * time.Second
	}
	if cfg.WSPongWaitSec > 0 {
		s.pongWait = time.Duration(cfg.WSPongWaitSec) * time.Second
	}
	if cfg.WSPingIntervalSec > 0 {
		s.pingInterval = time.Duration(cfg.WSPingIntervalSec) * time.Second
	}
	if s.pingInterval >= s.pongWait {
		s.pingInterval = s.pongWait / 2
	}
	if cfg.WSReadLimitBytes > 0 {
		s.readLimit = int64(cfg.WSReadLimitBytes)
	}

	s.webrtcAPI = newWebRTCAPI(cfg.UDPPortMin, cfg.UDPPortMax, s.log)
	s.iceServers = parseBootstrapIceServers(cfg.IceServers)
	s.mediaQuality = cfg.MediaQuality
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
