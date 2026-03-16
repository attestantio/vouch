# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build binary with CGO (required for BLS cryptography library)
# -ldflags -s -w: Strip symbols and debug info for smaller binary
RUN CGO_ENABLED=1 go build \
    -ldflags '-s -w' \
    -o vouch .

# Runtime stage - Distroless base (includes CA certificates) with nonroot user
FROM gcr.io/distroless/base-debian12:nonroot

# Copy binary with correct ownership for nonroot user
COPY --from=builder --chown=nonroot:nonroot /app/vouch /app/vouch

WORKDIR /app

# Set base directory for config file discovery (looks for /app/vouch.yml)
ENV VOUCH_BASE_DIR=/app

# Run as nonroot (UID 65532, GID 65532)
USER nonroot:nonroot

ENTRYPOINT ["/app/vouch"]
