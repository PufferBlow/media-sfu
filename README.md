<div align="center">

<img src="https://raw.githubusercontent.com/PufferBlow/client/main/public/pufferblow-logo.svg" width="120" alt="Pufferblow logo" />

# Pufferblow media-sfu

**The WebRTC media plane for Pufferblow voice channels.**

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Pion WebRTC](https://img.shields.io/badge/Pion-WebRTC-v4-blue?style=flat-square)](https://github.com/pion/webrtc)
[![CI](https://img.shields.io/github/actions/workflow/status/PufferBlow/media-sfu/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/PufferBlow/media-sfu/actions)
[![GitHub Stars](https://img.shields.io/github/stars/PufferBlow/media-sfu?style=flat-square&color=yellow)](https://github.com/PufferBlow/media-sfu/stargazers)

</div>

---

## Overview

`media-sfu` is the dedicated real-time media plane for Pufferblow. It handles WebRTC peer sessions, RTP audio forwarding, and participant lifecycle events for voice channels.

It is designed to run alongside the main Pufferblow API, which acts as the control plane — issuing join tokens, enforcing authentication, and storing session state. `media-sfu` does none of that; it only forwards media and calls back to the API for authoritative decisions.

### Design goals

- Voice-first SFU (Selective Forwarding Unit) — low latency, no media transcoding
- Scales to **100+ concurrent audio participants** across rooms on a single instance
- Tunable via shared `~/.pufferblow/config.toml` — no separate config file to manage
- Stateless between restarts (session state lives in the Pufferblow API's database)

---

## How It Fits Together

```
Client (browser / desktop app)
        │  WebSocket + WebRTC
        ▼
  ┌─────────────┐    bootstrap / callbacks    ┌─────────────────────┐
  │  media-sfu  │ ◄──────────────────────────► │  Pufferblow API     │
  │  (Go / Pion │                              │  (Python / FastAPI) │
  │   port 8787)│                              │  (port 7575)        │
  └─────────────┘                              └─────────────────────┘
        │  STUN / TURN (NAT traversal)
        ▼
     coturn
```

On startup, `media-sfu` fetches its runtime configuration from the Pufferblow API (`/api/internal/v1/voice/bootstrap-config`). After that, all communication is through internal callback endpoints signed with HMAC-SHA256.

---

## Requirements

- Go 1.24 or later
- A running [Pufferblow](https://github.com/PufferBlow/pufferblow) instance
- `~/.pufferblow/config.toml` with a `[media-sfu]` section (created by `pufferblow setup`)
- Optional: a TURN server (coturn) for clients behind strict NAT

---

## Running Locally

```bash
go mod download
go run ./cmd/server -config ~/.pufferblow/config.toml
```

The server binds to `:8787` by default (configurable via `bind_addr` in `config.toml`).

---

## Docker

```bash
docker build -t pufferblow-media-sfu .

docker run --rm -p 8787:8787 \
  -v "$HOME/.pufferblow:/root/.pufferblow:ro" \
  pufferblow-media-sfu
```

---

## Configuration

`media-sfu` reads the `[media-sfu]` section from the shared Pufferblow config file. Example:

```toml
[media-sfu]
bootstrap_config_url     = "http://localhost:7575/api/internal/v1/voice/bootstrap-config"
bootstrap_secret         = "change-this-secret"
bind_addr                = ":8787"
max_total_peers          = 1000
max_room_peers           = 100
room_end_grace_seconds   = 15
event_workers            = 4
event_queue_size         = 8192
http_timeout_seconds     = 5
ws_write_timeout_seconds = 4
ws_ping_interval_seconds = 20
ws_pong_wait_seconds     = 45
ws_read_limit_bytes      = 1048576
udp_port_min             = 50000
udp_port_max             = 51999
```

Run `pufferblow setup --setup-media-sfu` to generate and write this section interactively.

### ICE servers (STUN / TURN)

`media-sfu` doesn't ship its own STUN/TURN — it consumes the list the
Pufferblow API hands back in the bootstrap response (`ice_servers`). Each
entry can be either a single URL string or an array of URLs, with optional
`username` / `credential` for TURN.

Public STUN is enough for most home/office NATs. Carrier-grade NAT, mobile,
and corporate networks usually need a real TURN relay. The shortest
self-host path is [coturn](https://github.com/coturn/coturn):

```bash
docker run -d --name pufferblow-coturn --network host \
  -e DETECT_EXTERNAL_IP=yes -e DETECT_RELAY_IP=yes \
  coturn/coturn -n \
    --listening-port=3478 \
    --tls-listening-port=5349 \
    --realm=pufferblow.example.com \
    --use-auth-secret \
    --static-auth-secret=change-me \
    --no-multicast-peers \
    --no-cli
```

Then expose it to the SFU via the Pufferblow API's bootstrap config:

```json
{
  "ice_servers": [
    {"urls": "stun:stun.l.google.com:19302"},
    {
      "urls": ["turn:turn.example.com:3478", "turns:turn.example.com:5349"],
      "username": "pufferblow",
      "credential": "<short-lived-secret-or-shared>"
    }
  ]
}
```

At startup the SFU logs one `ICE server configured` line per entry. TURN
credentials are masked (`credential=***`) so logs are safe to share. If
no ICE servers are configured at all you'll see:

```
WARN  No ICE servers configured — peers behind strict NAT will fail to connect
```

That warning is a deployment smell; either you forgot to configure TURN or
your bootstrap endpoint isn't returning it.

> **Verification.** From a host behind your target NAT, run `chrome://webrtc-internals`
> (or `about:webrtc` on Firefox) during a voice connect. The remote-candidate
> stats should list at least one `relay` candidate when TURN is in use; if you
> only ever see `srflx` you're on STUN-only and clients behind symmetric NAT
> will be unable to join.

---

## API Endpoints

### Public (WebSocket signaling)

| Endpoint | Description |
|---|---|
| `GET /rtc/v1/ws?join_token=<token>` | Client WebSocket connection |

### Operational

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness check |
| `GET /readyz` | Readiness check |
| `GET /metrics` | JSON metrics snapshot |

### Internal callbacks (called by Pufferblow API)

These are not client-facing. All requests must carry a valid `X-Pufferblow-Signature` HMAC-SHA256 header.

| Endpoint | Description |
|---|---|
| `POST /api/internal/v1/voice/bootstrap-config` | Fetch runtime config at startup |
| `POST /api/internal/v1/voice/consume-join-token` | Validate and consume a one-time join token |
| `POST /api/internal/v1/voice/events` | Deliver participant lifecycle events |

---

## WebSocket Message Types

**Client → SFU**

`join` · `offer` · `answer` · `candidate` · `audio_state` · `ping`

**SFU → Client**

`joined` · `participant_joined` · `participant_left` · `offer` · `answer` · `candidate` · `speaker_levels` · `pong` · `error`

---

## Logging

Logs are written to stdout via Go `slog`. When stdout is a terminal, output is rendered in colour using [tint](https://github.com/lmittmann/tint). When piped to a file or log aggregator, plain structured text is used instead.

Log level is set via `log_level` in `config.toml` (`debug`, `info`, `warn`, `error`). Default is `info`.

---

## Testing

```bash
# Run unit tests
./scripts/run_test.sh

# Include concurrent join stress test
./scripts/run_test.sh --stress

# Include long-running soak test
./scripts/run_test.sh --soak

# Both stress and soak with higher defaults
./scripts/run_test.sh --heavy
```

Useful environment overrides:

```bash
STRESS_CLIENTS=256 ./scripts/run_test.sh --stress
SOAK_CLIENTS=64 SOAK_DURATION_SECONDS=120 ./scripts/run_test.sh --soak
BENCH_TIME=10x ./scripts/run_test.sh
```

> The stress and soak tests exercise the signaling path and control plane. They do not simulate sustained RTP media bandwidth across real peer streams.

---

## License

Released under the [GNU General Public License v3.0](LICENSE).
