# Pufferblow Media SFU

`media-sfu` is the dedicated real-time media plane for Pufferblow.

- Repository target: `https://github.com/pufferblow/media-sfu`
- Runtime: Go + Pion WebRTC
- Scope: SFU forwarding (voice-first), signaling, and control-plane callbacks to Pufferblow API
- Logs: human-readable text output on stdout via Go `slog`

## Architecture

- Control plane: `pufferblow` (Python/FastAPI) issues join tokens, enforces auth/permissions, stores session state.
- Media plane: `media-sfu` handles WebRTC peer sessions, RTP forwarding, and participant lifecycle.
- Relay plane: `coturn` handles NAT traversal/fallback.
- Configuration: `media-sfu` reads the shared Pufferblow config file at `~/.pufferblow/config.toml`, using the `[media-sfu]` section.

## Protocol

- WebSocket signaling endpoint:
  - `GET /rtc/v1/ws?join_token=<token>`
- Health and ops:
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics` (JSON metrics snapshot)

Pufferblow also mirrors SFU health through the instance control plane at:

- `GET /api/v1/system/instance-health`
- `GET /healthz`
- `GET /readyz`

That lets operators inspect Python control-plane health and nested SFU health
from the instance itself, even when `media-sfu` is deployed separately.

### Signaling message types

Client -> SFU:
- `join`
- `offer`
- `answer`
- `candidate`
- `audio_state`
- `ping`

SFU -> Client:
- `joined`
- `participant_joined`
- `participant_left`
- `offer`
- `answer`
- `candidate`
- `speaker_levels`
- `pong`
- `error`

## Internal API callbacks (to Pufferblow server)

Configured from server-provided bootstrap config at startup.

- `POST /consume-join-token`
- `POST /events`

Requests are signed with `X-Pufferblow-Signature: sha256=<hex>` using `RTC_INTERNAL_SECRET`.

## Scalability Baseline

This service is tuned for a practical first target of **100+ concurrent audio clients** (across channels/rooms) with:

- connection admission control:
  - `RTC_MAX_TOTAL_PEERS`
  - `RTC_MAX_ROOM_PEERS`
- bounded internal event queue + workers:
  - `RTC_INTERNAL_EVENT_WORKERS`
  - `RTC_INTERNAL_EVENT_QUEUE_SIZE`
- websocket keepalive and safety:
  - read limit, ping/pong timers, write timeout
- reconnect grace window for empty rooms:
  - `RTC_ROOM_END_GRACE` (default `15s`)
- fixed UDP port range for predictable infra/networking:
  - `RTC_UDP_PORT_MIN`
  - `RTC_UDP_PORT_MAX`
- metrics endpoint for capacity monitoring.

## Shared Config

`media-sfu` does not keep a repo-local config file. It reads the global Pufferblow config at:

- Linux/macOS: `~/.pufferblow/config.toml`
- Docker compose in this repo: `/root/.pufferblow/config.toml`

The media-plane settings live under the `[media-sfu]` section in that shared file. All operational settings (bootstrap URL/secret, bind address, queue/timeouts, peer limits, UDP range) are sourced from there.

## Local Run

```bash
go mod download
go run ./cmd/server -config ~/.pufferblow/config.toml
```

## Testing

The repo includes:

- unit tests for config, signing, and bootstrap helpers
- a signaling benchmark: `BenchmarkMediaSFUSignalingJoin`
- a concurrent join stress test: `TestMediaSFUSignalingStress`
- a churn-oriented soak test: `TestMediaSFUSignalingSoak`

Use the bundled runner:

```bash
./scripts/run_test.sh
```

Default behavior:

- runs `go test ./...`
- runs the signaling benchmark
- skips stress and soak tests unless explicitly enabled

Runner modes:

```bash
./scripts/run_test.sh --stress
./scripts/run_test.sh --soak
./scripts/run_test.sh --heavy
```

- `--stress`: runs the concurrent join test with the configured client count
- `--soak`: runs the longer churn test at fixed concurrency for a bounded duration
- `--heavy`: enables both stress and soak with larger benchmark-oriented defaults

Useful environment overrides:

```bash
BENCH_TIME=10x ./scripts/run_test.sh
STRESS_CLIENTS=256 ./scripts/run_test.sh --stress
SOAK_CLIENTS=64 SOAK_DURATION_SECONDS=120 SOAK_HOLD_MILLISECONDS=250 ./scripts/run_test.sh --soak
```

Supported runner environment variables:

- `UNIT_TEST_PATTERN`
- `BENCH_PATTERN`
- `BENCH_TIME`
- `RUN_STRESS`
- `STRESS_CLIENTS`
- `STRESS_TEST_PATTERN`
- `RUN_SOAK`
- `SOAK_CLIENTS`
- `SOAK_DURATION_SECONDS`
- `SOAK_HOLD_MILLISECONDS`
- `SOAK_TEST_PATTERN`

Important scope note:

- the benchmark, stress, and soak tests exercise the SFU control plane and websocket signaling path
- they do not simulate sustained RTP media forwarding bandwidth across real peer media streams

## Docker

```bash
docker build -t pufferblow-media-sfu .
docker run --rm -p 8787:8787 \
  -v "$HOME/.pufferblow:/root/.pufferblow:ro" \
  pufferblow-media-sfu
```

## Server Integration (Compose)

The server compose file is configured to build SFU from this dedicated repo using:

`MEDIA_SFU_GIT_CONTEXT=https://github.com/pufferblow/media-sfu.git`

This keeps `pufferblow` (server) and `media-sfu` (media plane) independently versioned and deployable.

## Split and Publish as Separate Repo

If you are splitting from this monorepo, use:

```bash
git -C pufferblow subtree split --prefix=media-sfu -b media-sfu-split
git -C pufferblow push https://github.com/pufferblow/media-sfu.git media-sfu-split:main
```

Then future updates can be pushed from the dedicated repo directly.
