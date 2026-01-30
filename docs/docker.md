# Running Vouch with Docker

## Official Image

Vouch is available on Docker Hub:

```bash
docker pull attestant/vouch:latest
```

## Building from Source

```bash
git clone https://github.com/attestantio/vouch.git
cd vouch
docker build -t vouch:local .
```

Note: The build requires CGO enabled due to the BLS cryptography library (`herumi/bls-eth-go-binary`). The Dockerfile uses `distroless/base-debian12` which includes glibc to support this.

## Running

Mount your config file to `/app/vouch.yml`:

```bash
docker run -v /path/to/vouch.yml:/app/vouch.yml:ro attestant/vouch:latest
```

The image has `VOUCH_BASE_DIR=/app` set by default, so Vouch automatically looks for `/app/vouch.yml`.

### Volume Permissions

The container runs as a non-root user (UID 65532). Mounted files must be readable by this user. Either make files world-readable:

```bash
chmod 644 /path/to/vouch.yml
```

Or set ownership to the nonroot user:

```bash
chown 65532:65532 /path/to/vouch.yml
```

### Ports

Vouch uses the following ports (configure in vouch.yml):

| Port | Purpose |
|------|---------|
| 18550 | Block relay service |
| 8081 | Prometheus metrics (optional) |

## Security Notes

The Docker image uses Google's Distroless base with the following characteristics:

- **Minimal attack surface** - No shell, package manager, or unnecessary binaries
- **Non-root execution** - Runs as UID 65532 for improved security
- **CA certificates** - Included and maintained by Google

Note: Since there is no shell, `docker exec` cannot be used for debugging. Use Vouch's logging and metrics endpoints for observability.
