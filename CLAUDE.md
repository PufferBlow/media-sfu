# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`media-sfu` is the WebRTC media plane for Pufferblow voice channels — a Go SFU (Selective Forwarding Unit) built on `pion/webrtc/v4`. It forwards RTP audio/video between peers in a room; it does not transcode media. It is one of four sibling repos in the Pufferblow workspace:

- `pufferblow/` — the Python/FastAPI control plane (issues join tokens, owns session state, port 7575)
- `client/` — Electron/web frontend
- `media-sfu/` (this repo) — Go WebRTC SFU, port 8787
- `pypufferblow/` — Python SDK

`media-sfu` is intentionally stateless and dumb about auth: it validates every join token and authorizes every event against the Pufferblow API rather than deciding anything itself. Session state lives in the Pufferblow API's database, not here.

The entire server implementation lives in a single file, `cmd/server/main.go` (~2200 lines), organized into clearly commented sections (Config, Server, Room lifecycle, Track fanout, WebSocket handler, etc.) rather than split into packages. When editing, preserve that section structure (the `// ─── Section ───` banner comments) instead of introducing new files/packages unless there's a strong reason.

## Commands

```bash
# Run locally (reads config from ~/.pufferblow/config.toml by default)
go run ./cmd/server -config ~/.pufferblow/config.toml

# Build
go build -o server ./cmd/server

# Unit tests only
go test ./...

# Full local test suite (unit + benchmark; stress/soak are opt-in)
./scripts/run_test.sh
./scripts/run_test.sh --stress   # + concurrent-join stress test (TestMediaSFUSignalingStress)
./scripts/run_test.sh --soak     # + long-running soak test (TestMediaSFUSignalingSoak)
./scripts/run_test.sh --heavy    # both, with larger client counts / longer duration

# Env overrides for the above (see scripts/run_test.sh for the full list)
STRESS_CLIENTS=256 ./scripts/run_test.sh --stress
SOAK_CLIENTS=64 SOAK_DURATION_SECONDS=120 ./scripts/run_test.sh --soak
BENCH_TIME=10x ./scripts/run_test.sh

# Single test / targeted run
go test ./cmd/server -run TestRewriteKeyframeRequestsRewritesPLI -v

# Docker
docker build -t pufferblow-media-sfu .
docker run --rm -p 8787:8787 -v "$HOME/.pufferblow:/root/.pufferblow:ro" pufferblow-media-sfu
```

There is no CI workflow file in this repo (`.github/workflows` does not exist) and no Makefile, despite the README's CI badge — treat `go test ./...` and `./scripts/run_test.sh` as the source of truth for verification. No linter config either; `go vet`/`gofmt` are the only implicit standards.

Go 1.24+ is required by `go.mod` (the Dockerfile builder stage pins `golang:1.22-alpine`, which is stale relative to go.mod — don't assume the Dockerfile's Go version is authoritative).

## Configuration model

Config is **not** read from environment variables or CLI flags (other than `-config` for the file path). Everything comes from the shared `~/.pufferblow/config.toml`, under a `[media-sfu]` table (`MediaSFUConfig` struct, `loadConfigFromTOML`). Precedence, highest first:

1. Values returned by the Pufferblow API's bootstrap endpoint (fetched at startup, see below) — these override local TOML for most fields (peer limits, event worker count, WS timeouts, UDP port range, etc.)
2. Local `config.toml` `[media-sfu]` values
3. Hardcoded fallback defaults in `newServer()`

`bootstrap_secret` in the local TOML is the one thing that must be present locally (it's not something the bootstrap call can provide — it's used to authenticate the bootstrap call itself). Startup fails fast if it's missing.

## Architecture: bootstrap, auth, and the control-plane relationship

On startup (`newServer` → `fetchBootstrapConfigWithRetry`):

1. The SFU POSTs to the Pufferblow API's `/api/internal/v1/voice/bootstrap-config` endpoint, HMAC-SHA256-signed with `bootstrap_secret` (timestamp + nonce + body, see `signBootstrapPayload`). Retries with a delay (`bootstrap_max_retries` / `bootstrap_retry_delay`) since the API may not be up yet.
2. The response (`sfuBootstrapConfig`) supplies `internal_api_base` + `internal_secret` — the credentials used for **all subsequent** internal calls back to the API — plus ICE servers, media quality profiles, and operational tuning values that override local config.
3. From then on, every call to the Pufferblow API (consuming join tokens, posting lifecycle events) is signed with `internal_secret` via the `X-Pufferblow-Signature` header (`signPayload`), not `bootstrap_secret`. The two secrets serve different trust boundaries: `bootstrap_secret` proves the SFU is legitimate before it has any API-issued credentials; `internal_secret` is what the API hands back for ongoing calls.

Client-facing auth is entirely delegated: a WebSocket connection to `/rtc/v1/ws?join_token=<token>` triggers `consumeJoinToken`, which POSTs the token to the API's `/consume-join-token` endpoint. The API is the only party that can mint or validate tokens; the SFU just relays the one-time token and trusts the `joinClaims` the API hands back (`sub`, `session_id`, `channel_id`, `scope`, etc.). A token must carry at least one of `recv` / `send_audio` / `send_video` in `scope` or it's rejected. Scope is enforced at the WebRTC level too: `pc.OnTrack` drains (rather than forwards) any incoming track the peer's scope doesn't permit.

Participant lifecycle events (`participant_joined`, `participant_left`, `state_changed`, `screen_share_changed`, `session_ended`) are pushed back to the API asynchronously via a bounded channel (`eventQueue`) drained by a pool of worker goroutines (`startEventWorkers`, sized by `event_workers`). If the queue is full, events are dropped (counted in `droppedInternalEvents`) rather than blocking — the SFU prioritizes not stalling media over guaranteed event delivery.

## Architecture: rooms, peers, and track fanout

- **Room** = one voice channel session (`sessionID` keyed), holding a map of `peer`s and a map of `roomTrack`s. Created lazily on first join (`getOrCreateRoom`), torn down after a grace period (`room_end_grace_seconds`, default 15s) once empty (`scheduleRoomEndGrace`) — the grace period absorbs quick reconnects without flapping `session_ended` events to the API.
- **Peer** = one WebSocket + one `pion` `PeerConnection`. Mute/deafen/speaking/screen-share state is guarded by its own `stateMu`, deliberately separate from the room's lock, so that broadcasting participant snapshots never has to hold the room lock while touching per-peer state (see the comment on the `peer` struct).
- **Track fanout** (`handleRemoteTrack`): when a peer publishes a track, the SFU creates one `TrackLocalStaticRTP` per source track and fans it out to every other current room member in parallel goroutines (`addTrackToPeer` renegotiates via a fresh offer per target). New joiners get all currently-live tracks fanned to them the same way. This is an SFU, not an MCU — no mixing, just per-receiver forwarding, so peer count × track count drives the renegotiation fan-out cost.
- **RTCP plumbing** (`forwardReceiverRTCP`): a goroutine per fanned-out track drains RTCP from each receiver's `RTPSender` (mandatory — pion stalls the sender otherwise) and:
  - Rewrites and re-emits PLI/FIR (keyframe requests) back to the original publisher with the publisher's SSRC substituted in (`rewriteKeyframeRequests`).
  - Aggregates REMB (bandwidth estimate) across all receivers of a track, taking the **minimum** reported bitrate, and forwards that aggregate to the publisher when it changes significantly (>20%) or every 2s as a heartbeat (`roomTrack.shouldForwardREMB`). This is how one slow receiver throttles the publisher's upload encoder for everyone.
- Capacity is enforced at two points: a lock-free atomic counter (`reservePeerSlot`/`totalPeers`) for the global `max_total_peers`, and an authoritative recheck under the room lock for `max_room_peers` once a peer is about to be registered (handles the race between the optimistic pre-check and lock acquisition).

## Concurrency model

Goroutine-per-connection plus goroutine-per-track-direction:

- One goroutine for the WebSocket read loop (signaling: offer/answer/candidate/audio_state/screen_share/ping).
- One goroutine per published remote track pumping RTP from `TrackRemote` → local `TrackLocalStaticRTP` (`handleRemoteTrack`).
- One goroutine per fanned-out track-receiver pair pumping RTCP in the reverse direction (`forwardReceiverRTCP`).
- One ping-keepalive goroutine per peer.
- A small worker pool for outbound internal API events (decoupled from the hot media/signaling path via `eventQueue`).

Locking is deliberately layered: `sfuServer.roomsMu` guards the rooms map, `room.Mu` guards a room's peers/tracks maps, `peer.stateMu` guards mutable peer state, `roomTrack.rembMu` guards REMB bookkeeping, and `peer.WriteMu` serializes WebSocket writes (gorilla/websocket requires single-writer). Snapshot operations (`room.snapshots()`, `peer.snapshot()`) are structured to copy data out from under one lock before touching another, specifically to avoid holding the room lock while iterating per-peer state.

## WebSocket protocol

Single endpoint: `GET /rtc/v1/ws?join_token=<token>`.

Client → SFU message types: `join`, `offer`, `answer`, `candidate`, `audio_state`, `screen_share_started`/`screen_share_stopped`, `ping`.
SFU → Client message types: `joined`, `participant_joined`, `participant_left`, `offer`, `answer`, `candidate`, `speaker_levels`, `screen_share_started`/`screen_share_stopped`, `pong`, `error`.

Other HTTP endpoints: `GET /healthz`, `GET /readyz` (both liveness/readiness, same handler), `GET /metrics` (JSON snapshot; requires `X-Pufferblow-Signature` if `metrics_secret` is configured).

## Testing notes

- `cmd/server/main_test.go` — unit tests for pure/testable logic: TOML config loading, HMAC signing, ICE server parsing/log-masking, RTCP rewriting (PLI/FIR), REMB aggregation and throttling logic on `roomTrack`.
- `cmd/server/stress_test.go` — `BenchmarkMediaSFUSignalingJoin`, plus opt-in `TestMediaSFUSignalingStress` / `TestMediaSFUSignalingSoak`, gated behind `MEDIA_SFU_STRESS=1` / `MEDIA_SFU_SOAK=1` env vars (set automatically by `scripts/run_test.sh --stress`/`--soak`). These exercise the signaling path and control-plane event flow at scale; they do **not** simulate sustained real RTP media bandwidth across peer streams, so they won't catch media-forwarding regressions.
- When touching REMB/PLI/FIR logic, the pure-logic helpers (`rewriteKeyframeRequests`, `extractMaxBitrateBPS`, `roomTrack.shouldForwardREMB`) are intentionally extracted so they're testable without a live `pion` `RTPSender`/connection — keep new RTCP logic in that shape rather than burying it inline in `forwardReceiverRTCP`.
