package sfu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

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

	// Multi-instance SFU registry (see pufferblow's media_sfu_instances
	// table). All three are static per-deployment identity, not something
	// the bootstrap-config response overrides.
	InstanceID               string `toml:"instance_id"`
	Region                   string `toml:"region"`
	PublicSignalingURL       string `toml:"public_signaling_url"`
	HeartbeatIntervalSeconds int    `toml:"heartbeat_interval_seconds"`
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

func DefaultConfigPath() string {
	candidates := []string{
		"/root/.pufferblow/config.toml",
	}

	if homeDir, err := os.UserHomeDir(); err == nil && strings.TrimSpace(homeDir) != "" {
		candidates = append(
			[]string{filepath.Join(homeDir, ".pufferblow", "config.toml")},
			candidates...,
		)
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return candidates[0]
}
