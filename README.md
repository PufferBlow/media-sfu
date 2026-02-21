# Pufferblow Media SFU

`media-sfu` is the dedicated real-time media plane for Pufferblow.

- Repository target: `https://github.com/pufferblow/media-sfu`
- Runtime: Go + Pion WebRTC
- Scope: SFU forwarding (voice-first), signaling, and control-plane callbacks to Pufferblow API

## Architecture

- Control plane: `pufferblow` (Python/FastAPI) issues join tokens, enforces auth/permissions, stores session state.
- Media plane: `media-sfu` handles WebRTC peer sessions, RTP forwarding, and participant lifecycle.
- Relay plane: `coturn` handles NAT traversal/fallback.

## Protocol

- WebSocket signaling endpoint:
  - `GET /rtc/v1/ws?join_token=<token>`
- Health and ops:
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics` (JSON metrics snapshot)

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

## Environment Variables

Core:
- `RTC_BIND_ADDR` (default `:8787`)
- `RTC_BOOTSTRAP_CONFIG_URL` (default `http://localhost:7575/api/internal/v1/voice/bootstrap-config`)
- `RTC_BOOTSTRAP_SECRET` (required)
- `RTC_BOOTSTRAP_HTTP_TIMEOUT` (default `5s`)

All operational settings (ICE servers, internal callback secret/base, queue/timeouts, peer limits, UDP range) are fetched securely from the server runtime config.

## Local Run

```bash
go mod download
go run ./cmd/server
```

## Docker

```bash
docker build -t pufferblow-media-sfu .
docker run --rm -p 8787:8787 \
  -e RTC_BOOTSTRAP_SECRET=change-me \
  -e RTC_BOOTSTRAP_CONFIG_URL=http://host.docker.internal:7575/api/internal/v1/voice/bootstrap-config \
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
