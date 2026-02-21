FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/media-sfu ./cmd/server

FROM alpine:3.21
RUN adduser -D -H appuser
USER appuser
WORKDIR /
COPY --from=builder /out/media-sfu /media-sfu
EXPOSE 8787
ENTRYPOINT ["/media-sfu"]

