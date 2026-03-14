package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type stressBackend struct {
	tb              testing.TB
	server          *httptest.Server
	bootstrapSecret string
	internalSecret  string

	mu       sync.Mutex
	claims   map[string]joinClaims
	consumed map[string]time.Time

	eventCount atomic.Int64
}

func newStressBackend(tb testing.TB) *stressBackend {
	tb.Helper()

	backend := &stressBackend{
		tb:              tb,
		bootstrapSecret: "stress-bootstrap-secret",
		internalSecret:  "stress-internal-secret",
		claims:          make(map[string]joinClaims),
		consumed:        make(map[string]time.Time),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/bootstrap-config", backend.handleBootstrapConfig)
	mux.HandleFunc("/consume-join-token", backend.handleConsumeJoinToken)
	mux.HandleFunc("/events", backend.handleEvents)

	backend.server = httptest.NewServer(mux)
	return backend
}

func (b *stressBackend) close() {
	if b.server != nil {
		b.server.Close()
	}
}

func (b *stressBackend) issueJoinToken(userID, sessionID, channelID string) string {
	b.tb.Helper()

	now := time.Now().UTC()
	token := fmt.Sprintf("%s|%s|%s|%d", sessionID, channelID, userID, now.UnixNano())
	b.mu.Lock()
	b.claims[token] = joinClaims{
		Sub:        userID,
		Username:   userID,
		InstanceID: "stress-instance",
		ServerID:   "stress-server",
		ChannelID:  channelID,
		SessionID:  sessionID,
		Scope:      "recv send_audio",
		Iat:        now.Unix(),
		Exp:        now.Add(10 * time.Minute).Unix(),
		JTI:        token,
	}
	b.mu.Unlock()
	return token
}

func (b *stressBackend) handleBootstrapConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !validateBootstrapRequest(r, b.bootstrapSecret, body) {
		http.Error(w, "invalid bootstrap signature", http.StatusUnauthorized)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	if payload["service"] != "media-sfu" {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}
	if payload["nonce"] != r.Header.Get("X-Pufferblow-Nonce") {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, bootstrapConfigResponse{
		StatusCode: http.StatusOK,
		Config: sfuBootstrapConfig{
			InternalAPIBase:        b.server.URL,
			InternalSecret:         b.internalSecret,
			MaxTotalPeers:          512,
			MaxRoomPeers:           512,
			RoomEndGraceSeconds:    1,
			InternalEventWorkers:   2,
			InternalEventQueueSize: 2048,
			InternalHTTPTimeoutSec: 5,
			WSWriteTimeoutSec:      4,
			WSPingIntervalSec:      30,
			WSPongWaitSec:          60,
			WSReadLimitBytes:       1_048_576,
			UDPPortMin:             50000,
			UDPPortMax:             50032,
			IceServers: []bootstrapIceServer{
				{URLs: "stun:stun.l.google.com:19302"},
			},
		},
	})
}

func (b *stressBackend) handleConsumeJoinToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !validateSignedPayload(r, b.internalSecret, body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var payload struct {
		JoinToken string `json:"join_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	claims, ok := b.claims[payload.JoinToken]
	if !ok {
		http.Error(w, "unknown join token", http.StatusUnauthorized)
		return
	}
	if _, consumed := b.consumed[payload.JoinToken]; consumed {
		http.Error(w, "join token already consumed", http.StatusUnauthorized)
		return
	}
	b.consumed[payload.JoinToken] = time.Now().UTC()

	writeJSON(w, http.StatusOK, consumeTokenResponse{
		StatusCode: http.StatusOK,
		Claims:     claims,
	})
}

func (b *stressBackend) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !validateSignedPayload(r, b.internalSecret, body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var payload struct {
		EventType string         `json:"event_type"`
		Payload   map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.EventType) == "" {
		http.Error(w, "missing event_type", http.StatusBadRequest)
		return
	}

	b.eventCount.Add(1)
	writeJSON(w, http.StatusAccepted, map[string]any{"status_code": http.StatusAccepted})
}

type stressHarness struct {
	tb      testing.TB
	backend *stressBackend
	server  *sfuServer
	httpSrv *httptest.Server
}

func newStressHarness(tb testing.TB) *stressHarness {
	tb.Helper()

	backend := newStressBackend(tb)
	configPath := writeStressConfig(tb, backend.server.URL, backend.bootstrapSecret)

	server, err := newServer(configPath)
	if err != nil {
		backend.close()
		tb.Fatalf("newServer failed: %v", err)
	}
	server.startEventWorkers()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.healthz)
	mux.HandleFunc("/readyz", server.healthz)
	mux.HandleFunc("/metrics", server.metrics)
	mux.HandleFunc("/rtc/v1/ws", server.handleWS)

	return &stressHarness{
		tb:      tb,
		backend: backend,
		server:  server,
		httpSrv: httptest.NewServer(mux),
	}
}

func (h *stressHarness) close() {
	if h.httpSrv != nil {
		h.httpSrv.Close()
	}
	if h.server != nil {
		waitForTotalPeers(h.server, 0, 5*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		h.server.shutdown(ctx)
		cancel()
	}
	if h.backend != nil {
		h.backend.close()
	}
}

func (h *stressHarness) wsURL(joinToken string) string {
	wsURL := strings.Replace(h.httpSrv.URL, "http://", "ws://", 1)
	u, err := url.Parse(wsURL)
	if err != nil {
		h.tb.Fatalf("parse websocket url: %v", err)
	}
	u.Path = "/rtc/v1/ws"
	q := u.Query()
	q.Set("join_token", joinToken)
	u.RawQuery = q.Encode()
	return u.String()
}

type stressClient struct {
	conn *websocket.Conn

	joinedCh chan struct{}
	errCh    chan error
	doneCh   chan struct{}
	joinOnce sync.Once
}

func (h *stressHarness) connectClient(joinToken string, timeout time.Duration) (*stressClient, time.Duration, error) {
	start := time.Now()
	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL(joinToken), nil)
	if err != nil {
		return nil, 0, err
	}

	client := &stressClient{
		conn:     conn,
		joinedCh: make(chan struct{}),
		errCh:    make(chan error, 1),
		doneCh:   make(chan struct{}),
	}

	go client.readLoop()

	select {
	case <-client.joinedCh:
		return client, time.Since(start), nil
	case err := <-client.errCh:
		client.close()
		return nil, time.Since(start), err
	case <-time.After(timeout):
		client.close()
		return nil, time.Since(start), fmt.Errorf("timed out waiting for joined message")
	}
}

func (c *stressClient) readLoop() {
	defer close(c.doneCh)

	for {
		var msg signalMessage
		if err := c.conn.ReadJSON(&msg); err != nil {
			select {
			case c.errCh <- err:
			default:
			}
			return
		}

		switch msg.Type {
		case "joined":
			c.joinOnce.Do(func() { close(c.joinedCh) })
		case "error":
			select {
			case c.errCh <- fmt.Errorf("sfu error: %s", msg.Error):
			default:
			}
			return
		}
	}
}

func (c *stressClient) close() {
	if c.conn == nil {
		return
	}
	_ = c.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "stress test done"),
		time.Now().Add(time.Second),
	)
	_ = c.conn.Close()
	<-c.doneCh
}

func BenchmarkMediaSFUSignalingJoin(b *testing.B) {
	harness := newStressHarness(b)
	defer harness.close()

	var counter atomic.Int64
	var firstErr error
	var errOnce sync.Once
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := counter.Add(1)
			token := harness.backend.issueJoinToken(
				fmt.Sprintf("bench-user-%d", id),
				"benchmark-session",
				"benchmark-channel",
			)

			client, _, err := harness.connectClient(token, 5*time.Second)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
				return
			}
			client.close()
		}
	})

	if firstErr != nil {
		b.Fatalf("connectClient failed: %v", firstErr)
	}
}

func TestMediaSFUSignalingStress(t *testing.T) {
	if os.Getenv("MEDIA_SFU_STRESS") == "" {
		t.Skip("set MEDIA_SFU_STRESS=1 to run the media-sfu stress test")
	}

	clientCount := getenvInt("MEDIA_SFU_STRESS_CLIENTS", 64)
	if clientCount < 1 {
		t.Fatal("MEDIA_SFU_STRESS_CLIENTS must be at least 1")
	}

	harness := newStressHarness(t)
	defer harness.close()

	clients := make([]*stressClient, clientCount)
	latencies := make([]time.Duration, clientCount)
	defer func() {
		for _, client := range clients {
			if client != nil {
				client.close()
			}
		}
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, clientCount)
	start := time.Now()

	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			token := harness.backend.issueJoinToken(
				fmt.Sprintf("stress-user-%03d", idx),
				"stress-session",
				"stress-channel",
			)
			client, latency, err := harness.connectClient(token, 10*time.Second)
			if err != nil {
				errCh <- fmt.Errorf("client %d connect failed: %w", idx, err)
				return
			}

			clients[idx] = client
			latencies[idx] = latency
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	elapsed := time.Since(start)

	if got := connectedPeers(harness.server, "stress-session"); got != clientCount {
		t.Fatalf("expected %d connected peers, got %d", clientCount, got)
	}

	avgLatency, p50Latency, p95Latency := summarizeLatencies(latencies)
	throughput := float64(clientCount) / elapsed.Seconds()

	t.Logf(
		"media-sfu stress summary: clients=%d total=%s avg=%s p50=%s p95=%s throughput=%.2f joins/sec events=%d",
		clientCount,
		elapsed,
		avgLatency,
		p50Latency,
		p95Latency,
		throughput,
		harness.backend.eventCount.Load(),
	)
}

func TestMediaSFUSignalingSoak(t *testing.T) {
	if os.Getenv("MEDIA_SFU_SOAK") == "" {
		t.Skip("set MEDIA_SFU_SOAK=1 to run the media-sfu soak test")
	}

	clientCount := getenvInt("MEDIA_SFU_SOAK_CLIENTS", 32)
	durationSeconds := getenvInt("MEDIA_SFU_SOAK_DURATION_SECONDS", 30)
	holdMilliseconds := getenvInt("MEDIA_SFU_SOAK_HOLD_MILLISECONDS", 250)
	if clientCount < 1 {
		t.Fatal("MEDIA_SFU_SOAK_CLIENTS must be at least 1")
	}
	if durationSeconds < 1 {
		t.Fatal("MEDIA_SFU_SOAK_DURATION_SECONDS must be at least 1")
	}
	if holdMilliseconds < 0 {
		t.Fatal("MEDIA_SFU_SOAK_HOLD_MILLISECONDS must be non-negative")
	}

	harness := newStressHarness(t)
	defer harness.close()

	soakDuration := time.Duration(durationSeconds) * time.Second
	holdDuration := time.Duration(holdMilliseconds) * time.Millisecond
	deadline := time.Now().Add(soakDuration)

	var cycles atomic.Int64
	var failures atomic.Int64
	var latencyMu sync.Mutex
	latencies := make([]time.Duration, 0, clientCount)
	errCh := make(chan error, clientCount)

	var wg sync.WaitGroup
	for workerID := 0; workerID < clientCount; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for iteration := 0; ; iteration++ {
				if time.Now().After(deadline) {
					return
				}

				token := harness.backend.issueJoinToken(
					fmt.Sprintf("soak-user-%03d-%06d", workerID, iteration),
					"soak-session",
					"soak-channel",
				)
				client, latency, err := harness.connectClient(token, 10*time.Second)
				if err != nil {
					failures.Add(1)
					select {
					case errCh <- fmt.Errorf("worker %d iteration %d connect failed: %w", workerID, iteration, err):
					default:
					}
					return
				}

				latencyMu.Lock()
				latencies = append(latencies, latency)
				latencyMu.Unlock()
				cycles.Add(1)

				if holdDuration > 0 {
					sleepUntil := time.Now().Add(holdDuration)
					if sleepUntil.After(deadline) {
						time.Sleep(time.Until(deadline))
					} else {
						time.Sleep(holdDuration)
					}
				}

				client.close()
			}
		}(workerID)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	if !waitForTotalPeers(harness.server, 0, 5*time.Second) {
		t.Fatalf("expected all peers to disconnect after soak run, remaining=%d", harness.server.totalPeers.Load())
	}

	avgLatency, p50Latency, p95Latency := summarizeLatencies(latencies)
	throughput := float64(cycles.Load()) / soakDuration.Seconds()

	t.Logf(
		"media-sfu soak summary: clients=%d duration=%s hold=%s cycles=%d failures=%d avg=%s p50=%s p95=%s throughput=%.2f joins/sec events=%d",
		clientCount,
		soakDuration,
		holdDuration,
		cycles.Load(),
		failures.Load(),
		avgLatency,
		p50Latency,
		p95Latency,
		throughput,
		harness.backend.eventCount.Load(),
	)
}

func writeStressConfig(tb testing.TB, bootstrapURL string, bootstrapSecret string) string {
	tb.Helper()

	tempDir := tb.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	content := fmt.Sprintf(`
[media-sfu]
bootstrap_config_url = %q
bootstrap_secret = %q
bind_addr = ":8787"
max_total_peers = 512
max_room_peers = 512
room_end_grace_seconds = 1
event_workers = 2
event_queue_size = 2048
http_timeout_seconds = 5
ws_write_timeout_seconds = 4
ws_ping_interval_seconds = 30
ws_pong_wait_seconds = 60
ws_read_limit_bytes = 1048576
udp_port_min = 50000
udp_port_max = 50032
log_level = "error"
`, bootstrapURL+"/bootstrap-config", bootstrapSecret)

	if err := os.WriteFile(configPath, []byte(strings.TrimSpace(content)), 0o600); err != nil {
		tb.Fatalf("write stress config: %v", err)
	}

	return configPath
}

func validateBootstrapRequest(r *http.Request, secret string, body []byte) bool {
	timestampHeader := r.Header.Get("X-Pufferblow-Timestamp")
	nonceHeader := r.Header.Get("X-Pufferblow-Nonce")
	signatureHeader := r.Header.Get("X-Pufferblow-Signature")

	timestamp, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return false
	}

	expected := signBootstrapPayload(secret, timestamp, nonceHeader, body)
	return signatureHeader == expected
}

func validateSignedPayload(r *http.Request, secret string, body []byte) bool {
	return r.Header.Get("X-Pufferblow-Signature") == signPayload(secret, body)
}

func readRequestBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func connectedPeers(server *sfuServer, sessionID string) int {
	server.roomsMu.RLock()
	roomObj := server.rooms[sessionID]
	server.roomsMu.RUnlock()
	if roomObj == nil {
		return 0
	}

	roomObj.Mu.RLock()
	defer roomObj.Mu.RUnlock()
	return len(roomObj.Peers)
}

func waitForTotalPeers(server *sfuServer, expected int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if server.totalPeers.Load() == expected {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return server.totalPeers.Load() == expected
}

func summarizeLatencies(latencies []time.Duration) (time.Duration, time.Duration, time.Duration) {
	if len(latencies) == 0 {
		return 0, 0, 0
	}

	clone := append([]time.Duration(nil), latencies...)
	sort.Slice(clone, func(i, j int) bool { return clone[i] < clone[j] })

	var total time.Duration
	for _, latency := range clone {
		total += latency
	}

	p50Idx := len(clone) / 2
	p95Idx := int(float64(len(clone)-1) * 0.95)

	return total / time.Duration(len(clone)), clone[p50Idx], clone[p95Idx]
}

func getenvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
