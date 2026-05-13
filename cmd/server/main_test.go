package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

func TestJoinClaimsHasScope(t *testing.T) {
	claims := joinClaims{
		Scope: "recv send_audio send_video",
	}

	if !claims.hasScope("recv") {
		t.Fatal("expected recv scope to be present")
	}
	if !claims.hasScope("send_audio") {
		t.Fatal("expected send_audio scope to be present")
	}
	if claims.hasScope("admin") {
		t.Fatal("did not expect unknown scope to be present")
	}
}

func TestLoadConfigFromTOMLReadsMediaSFUSection(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	content := `
[media-sfu]
bootstrap_config_url = "http://localhost:7575/api/internal/v1/voice/bootstrap-config"
bootstrap_secret = "secret-value"
bind_addr = ":8787"
max_total_peers = 250
max_room_peers = 25
event_workers = 6
`
	if err := os.WriteFile(configPath, []byte(strings.TrimSpace(content)), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := loadConfigFromTOML(configPath)
	if err != nil {
		t.Fatalf("loadConfigFromTOML returned error: %v", err)
	}

	if cfg.BootstrapConfigURL != "http://localhost:7575/api/internal/v1/voice/bootstrap-config" {
		t.Fatalf("unexpected bootstrap_config_url: %q", cfg.BootstrapConfigURL)
	}
	if cfg.BootstrapSecret != "secret-value" {
		t.Fatalf("unexpected bootstrap_secret: %q", cfg.BootstrapSecret)
	}
	if cfg.BindAddr != ":8787" {
		t.Fatalf("unexpected bind_addr: %q", cfg.BindAddr)
	}
	if cfg.MaxTotalPeers != 250 {
		t.Fatalf("unexpected max_total_peers: %d", cfg.MaxTotalPeers)
	}
	if cfg.MaxRoomPeers != 25 {
		t.Fatalf("unexpected max_room_peers: %d", cfg.MaxRoomPeers)
	}
	if cfg.EventWorkers != 6 {
		t.Fatalf("unexpected event_workers: %d", cfg.EventWorkers)
	}
}

func TestDefaultSharedConfigPathPrefersHomeConfig(t *testing.T) {
	tempHome := t.TempDir()
	sharedDir := filepath.Join(tempHome, ".pufferblow")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("create shared config dir: %v", err)
	}

	configPath := filepath.Join(sharedDir, "config.toml")
	if err := os.WriteFile(configPath, []byte("[media-sfu]\n"), 0o600); err != nil {
		t.Fatalf("write home config: %v", err)
	}

	t.Setenv("HOME", tempHome)

	if got := defaultSharedConfigPath(); got != configPath {
		t.Fatalf("expected home config path %q, got %q", configPath, got)
	}
}

func TestDefaultSharedConfigPathFallsBackToHomeCandidateWhenMissing(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	expected := filepath.Join(tempHome, ".pufferblow", "config.toml")
	if got := defaultSharedConfigPath(); got != expected {
		t.Fatalf("expected fallback path %q, got %q", expected, got)
	}
}

func TestSignBootstrapPayload(t *testing.T) {
	secret := "bootstrap-secret"
	timestamp := int64(1_700_000_000)
	nonce := "abc123"
	body := []byte(`{"service":"media-sfu","nonce":"abc123"}`)

	got := signBootstrapPayload(secret, timestamp, nonce, body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("1700000000.abc123."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("unexpected bootstrap signature: got %q want %q", got, want)
	}
}

func TestSignPayload(t *testing.T) {
	secret := "internal-secret"
	body := []byte(`{"event_type":"participant_joined"}`)

	got := signPayload(secret, body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("unexpected payload signature: got %q want %q", got, want)
	}
}

func TestFetchBootstrapConfigSuccessSignsRequest(t *testing.T) {
	secret := "bootstrap-secret"
	var sawRequest bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true

		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %q", got)
		}

		timestampHeader := r.Header.Get("X-Pufferblow-Timestamp")
		nonceHeader := r.Header.Get("X-Pufferblow-Nonce")
		signatureHeader := r.Header.Get("X-Pufferblow-Signature")

		if timestampHeader == "" || nonceHeader == "" || signatureHeader == "" {
			t.Fatalf("missing bootstrap headers: ts=%q nonce=%q sig=%q", timestampHeader, nonceHeader, signatureHeader)
		}

		timestamp, err := strconv.ParseInt(timestampHeader, 10, 64)
		if err != nil {
			t.Fatalf("invalid timestamp header: %v", err)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["service"] != "media-sfu" {
			t.Fatalf("unexpected service field: %#v", body["service"])
		}
		if body["nonce"] != nonceHeader {
			t.Fatalf("body nonce %q did not match header nonce %q", body["nonce"], nonceHeader)
		}

		bodyBytes, _ := json.Marshal(body)
		expectedSignature := signBootstrapPayload(secret, timestamp, nonceHeader, bodyBytes)
		if signatureHeader != expectedSignature {
			t.Fatalf("unexpected request signature: got %q want %q", signatureHeader, expectedSignature)
		}

		writeJSON(w, http.StatusOK, bootstrapConfigResponse{
			StatusCode: http.StatusOK,
			Config: sfuBootstrapConfig{
				InternalAPIBase:        "http://server/api/internal/v1/voice",
				InternalSecret:         "internal-secret",
				MaxTotalPeers:          1000,
				MaxRoomPeers:           100,
				RoomEndGraceSeconds:    15,
				InternalEventWorkers:   4,
				InternalEventQueueSize: 8192,
				InternalHTTPTimeoutSec: 5,
				WSWriteTimeoutSec:      4,
				WSPingIntervalSec:      20,
				WSPongWaitSec:          45,
				WSReadLimitBytes:       1048576,
				UDPPortMin:             50000,
				UDPPortMax:             51999,
				IceServers: []bootstrapIceServer{
					{URLs: "stun:stun.l.google.com:19302"},
				},
				MediaQuality: mediaQualityBootstrap{
					DefaultProfile: "balanced",
					Audio: audioQualityBootstrap{
						SampleRateHz:  48000,
						Channels:      1,
						StereoEnabled: false,
						DTXEnabled:    true,
						FECEnabled:    true,
						Profiles: map[string]profileBitrate{
							"low":      {BitrateKbps: 24},
							"balanced": {BitrateKbps: 48},
							"high":     {BitrateKbps: 64},
						},
					},
					Video: videoQualityBootstrap{
						Profiles: map[string]videoProfile{
							"balanced": {
								BitrateKbps: 1500,
								Width:       1280,
								Height:      720,
								FPS:         30,
							},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	cfg, err := fetchBootstrapConfig(client, server.URL, secret)
	if err != nil {
		t.Fatalf("fetchBootstrapConfig returned error: %v", err)
	}

	if !sawRequest {
		t.Fatal("expected bootstrap request to be sent")
	}
	if cfg.InternalAPIBase != "http://server/api/internal/v1/voice" {
		t.Fatalf("unexpected internal_api_base: %q", cfg.InternalAPIBase)
	}
	if cfg.InternalSecret != "internal-secret" {
		t.Fatalf("unexpected internal_secret: %q", cfg.InternalSecret)
	}
	if cfg.MaxTotalPeers != 1000 || cfg.MaxRoomPeers != 100 {
		t.Fatalf("unexpected peer limits: total=%d room=%d", cfg.MaxTotalPeers, cfg.MaxRoomPeers)
	}
	if len(cfg.IceServers) != 1 {
		t.Fatalf("expected 1 ice server, got %d", len(cfg.IceServers))
	}
	if cfg.MediaQuality.DefaultProfile != "balanced" {
		t.Fatalf("unexpected default media profile: %q", cfg.MediaQuality.DefaultProfile)
	}
	if cfg.MediaQuality.Audio.Profiles["balanced"].BitrateKbps != 48 {
		t.Fatalf("unexpected balanced audio bitrate: %d", cfg.MediaQuality.Audio.Profiles["balanced"].BitrateKbps)
	}
	if cfg.MediaQuality.Video.Profiles["balanced"].Width != 1280 {
		t.Fatalf("unexpected balanced video width: %d", cfg.MediaQuality.Video.Profiles["balanced"].Width)
	}
}

func TestFetchBootstrapConfigReturnsErrorOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	_, err := fetchBootstrapConfig(client, server.URL, "secret")
	if err == nil {
		t.Fatal("expected bootstrap fetch to fail")
	}
	if !strings.Contains(err.Error(), "status=502") {
		t.Fatalf("expected status code in error, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "backend unavailable") {
		t.Fatalf("expected response body in error, got %q", err.Error())
	}
}

func TestParseBootstrapIceServers(t *testing.T) {
	entries := []bootstrapIceServer{
		{
			URLs: "stun:stun.l.google.com:19302",
		},
		{
			URLs:       []any{"turn:turn.example.com:3478", "turns:turn.example.com:5349", "   "},
			Username:   "alice",
			Credential: "secret",
		},
		{
			URLs: []any{42, true},
		},
		{
			URLs: "",
		},
	}

	got := parseBootstrapIceServers(entries)
	if len(got) != 2 {
		t.Fatalf("expected 2 valid ICE servers, got %d", len(got))
	}

	if !reflect.DeepEqual(got[0].URLs, []string{"stun:stun.l.google.com:19302"}) {
		t.Fatalf("unexpected first ICE urls: %#v", got[0].URLs)
	}
	if !reflect.DeepEqual(got[1].URLs, []string{"turn:turn.example.com:3478", "turns:turn.example.com:5349"}) {
		t.Fatalf("unexpected second ICE urls: %#v", got[1].URLs)
	}
	if got[1].Username != "alice" || got[1].Credential != "secret" {
		t.Fatalf("unexpected ICE auth payload: %+v", got[1])
	}
}

func TestSummarizeICEServersForLogMasksCredentials(t *testing.T) {
	servers := []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{
			URLs:       []string{"turn:turn.example.com:3478", "turns:turn.example.com:5349"},
			Username:   "alice",
			Credential: "super-secret-password",
		},
		{
			URLs:     []string{"turn:nocred.example.com:3478"},
			Username: "bob",
			// Credential intentionally absent — half-configured TURN.
		},
		{
			URLs:       []string{"turn:no-user.example.com:3478"},
			Credential: "leaked?",
		},
	}

	summary := summarizeICEServersForLog(servers)
	if len(summary) != 4 {
		t.Fatalf("expected 4 summary lines, got %d (%v)", len(summary), summary)
	}

	for i, line := range summary {
		if strings.Contains(line, "super-secret-password") || strings.Contains(line, "leaked?") {
			t.Fatalf("summary[%d] leaked credential: %q", i, line)
		}
	}

	if !strings.Contains(summary[0], "stun:stun.l.google.com:19302") {
		t.Fatalf("STUN-only entry not rendered: %q", summary[0])
	}
	if !strings.Contains(summary[1], "user=alice") || !strings.Contains(summary[1], "credential=***") {
		t.Fatalf("TURN-with-cred entry rendered wrong: %q", summary[1])
	}
	if !strings.Contains(summary[2], "user=bob") || !strings.Contains(summary[2], "credential=<missing>") {
		t.Fatalf("TURN-without-cred entry rendered wrong: %q", summary[2])
	}
	if !strings.Contains(summary[3], "credential=***") || !strings.Contains(summary[3], "no-user") {
		t.Fatalf("TURN-without-user entry rendered wrong: %q", summary[3])
	}
}

func TestSummarizeICEServersForLogHandlesEmpty(t *testing.T) {
	if got := summarizeICEServersForLog(nil); len(got) != 0 {
		t.Fatalf("expected nil servers to render empty, got %v", got)
	}
	if got := summarizeICEServersForLog([]webrtc.ICEServer{}); len(got) != 0 {
		t.Fatalf("expected empty slice to render empty, got %v", got)
	}
}

func TestRewriteKeyframeRequestsRewritesPLI(t *testing.T) {
	const publisherSSRC = uint32(0xDEADBEEF)
	receiverInput := []rtcp.Packet{
		&rtcp.PictureLossIndication{
			SenderSSRC: 0x11111111,
			MediaSSRC:  0x22222222, // receiver-side SSRC, must be rewritten
		},
	}

	out := rewriteKeyframeRequests(receiverInput, publisherSSRC)
	if len(out) != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", len(out))
	}
	pli, ok := out[0].(*rtcp.PictureLossIndication)
	if !ok {
		t.Fatalf("expected *rtcp.PictureLossIndication, got %T", out[0])
	}
	if pli.MediaSSRC != publisherSSRC {
		t.Fatalf("MediaSSRC not rewritten: got %#x, want %#x", pli.MediaSSRC, publisherSSRC)
	}
}

func TestRewriteKeyframeRequestsRewritesFIR(t *testing.T) {
	const publisherSSRC = uint32(0xC0FFEE00)
	original := &rtcp.FullIntraRequest{
		SenderSSRC: 0x11111111,
		MediaSSRC:  0x22222222,
		FIR: []rtcp.FIREntry{
			{SSRC: 0x33333333, SequenceNumber: 7},
		},
	}

	out := rewriteKeyframeRequests([]rtcp.Packet{original}, publisherSSRC)
	if len(out) != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", len(out))
	}
	fir, ok := out[0].(*rtcp.FullIntraRequest)
	if !ok {
		t.Fatalf("expected *rtcp.FullIntraRequest, got %T", out[0])
	}
	if fir.MediaSSRC != publisherSSRC {
		t.Fatalf("MediaSSRC not rewritten: got %#x, want %#x", fir.MediaSSRC, publisherSSRC)
	}
	if len(fir.FIR) != 1 || fir.FIR[0].SequenceNumber != 7 {
		t.Fatalf("FIR payload mutated unexpectedly: %+v", fir)
	}
	// Original must remain untouched — receiver's goroutine may still hold it.
	if original.MediaSSRC != 0x22222222 {
		t.Fatalf("original FIR mutated: %#x", original.MediaSSRC)
	}
}

func TestRewriteKeyframeRequestsDropsUnrelatedRTCP(t *testing.T) {
	const publisherSSRC = uint32(0xABCDEF01)
	packets := []rtcp.Packet{
		&rtcp.ReceiverReport{}, // not a keyframe request — must be ignored
		&rtcp.SenderReport{},
		&rtcp.SourceDescription{},
		&rtcp.PictureLossIndication{MediaSSRC: 0xFFFFFFFF},
	}

	out := rewriteKeyframeRequests(packets, publisherSSRC)
	if len(out) != 1 {
		t.Fatalf("expected only the PLI to be forwarded, got %d packets", len(out))
	}
	if _, ok := out[0].(*rtcp.PictureLossIndication); !ok {
		t.Fatalf("expected PLI in output, got %T", out[0])
	}
}

func TestRewriteKeyframeRequestsHandlesEmptyAndZeroSSRC(t *testing.T) {
	if got := rewriteKeyframeRequests(nil, 12345); len(got) != 0 {
		t.Fatalf("nil input must produce nil output, got %v", got)
	}
	if got := rewriteKeyframeRequests(
		[]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 1}},
		0,
	); len(got) != 0 {
		t.Fatalf("publisherSSRC=0 must short-circuit, got %v", got)
	}
}
