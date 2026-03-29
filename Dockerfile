FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

WORKDIR /app

ARG BUILDARCH
RUN <<-EOF
    set -e
    packages=""
    case "$BUILDARCH" in
        amd64) packages="$packages gcc-aarch64-linux-gnu g++-aarch64-linux-gnu" ;;
        arm64) packages="$packages gcc-x86-64-linux-gnu g++-x86-64-linux-gnu" ;;
        *) echo "unsupported build architecture: $BUILDARCH" >&2; exit 1 ;;
    esac
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y $packages
    apt-get clean
    rm -rf /var/lib/apt/lists/*
EOF

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN <<-EOF
    set -e
    if [ "$BUILDARCH" = "$TARGETARCH" ]; then
        export CC=gcc CXX=g++
    else
        case "$TARGETARCH" in
            amd64) export CC=x86_64-linux-gnu-gcc CXX=x86_64-linux-gnu-g++ ;;
            arm64) export CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ ;;
            *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;;
        esac
    fi
    CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH CC=$CC CXX=$CXX go build -o /app/vouch .
EOF

FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app

COPY --from=builder /app/vouch /app/vouch

ENTRYPOINT ["/app/vouch"]
