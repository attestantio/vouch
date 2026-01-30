# Docker Integration Testing for Vouch

This directory contains the Docker Compose setup for integration testing Vouch with Dirk (Distributed Remote Keymanager).

## Overview

The integration test validates:

- Vouch Docker image builds successfully
- Image runs as nonroot user (UID 65532)
- Distroless base image has no shell access
- Vouch loads mTLS certificates for Dirk connection
- Vouch metrics endpoint responds
- Vouch can communicate with Dirk using test certificates

## Prerequisites

- Docker (20.10+)
- Docker Compose (v2+)

## Quick Start

```bash
# 1. Setup test wallet (required once)
./setup.sh

# 2. Build and run the integration test
docker compose -f docker-compose.test.yml up --build

# 3. In another terminal, verify metrics endpoint
curl http://localhost:8081/metrics

# 4. Cleanup
docker compose -f docker-compose.test.yml down -v
```

## Services

### Dirk (`signer-test01:9091`)

- Distributed Remote Keymanager
- Uses `signer-test01` certificate (matches DNS SAN)
- Wallet: `TestWallet` with account `Validator1`
- Grants `client-test01` full access to `TestWallet`

### Beacon Mock (`beacon-mock:5052`)

- Minimal nginx mock for beacon node endpoints
- Provides `/eth/v1/node/health`, config, and genesis endpoints
- Sufficient for Vouch startup validation

### Vouch (`vouch-test`)

- Built from local Dockerfile
- Configured to connect to Dirk using `client-test01` certificate
- Metrics exposed on port 8081
- Block relay on port 18550

## Certificate Structure

The test uses existing certificates from `../resources/`:

| File | Purpose | CN/SAN |
|------|---------|--------|
| `Testing_certificate_authority.crt` | CA certificate | CN=Testing certificate authority |
| `signer-test01.crt/.key` | Dirk server certificate | CN=signer-test01, SAN=DNS:signer-test01 |
| `client-test01.crt/.key` | Vouch client certificate | CN=client-test01 |

## Validation Criteria

### Build Verification

| Check | Command | Expected |
|-------|---------|----------|
| Build succeeds | `docker compose build` | Exit 0 |
| Nonroot user | `docker inspect --format='{{.Config.User}}' vouch:integration-test` | `nonroot:nonroot` |
| No shell | `docker run --rm --entrypoint /bin/sh vouch:integration-test` | Fails with "not found" |
| Help works | `docker run --rm vouch:integration-test --help` | Shows usage |

### Integration Verification

| Check | Method | Expected |
|-------|--------|----------|
| Dirk starts | `docker logs dirk-test` | "Listening on 0.0.0.0:9091" |
| Vouch loads certs | `docker logs vouch-test \| grep -i dirk` | "Starting dirk account manager" |
| Metrics respond | `curl localhost:8081/metrics` | HTTP 200 with metrics |

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/docker-build.yml`) runs:

1. **docker-build** job (always):
   - Builds Docker image
   - Verifies nonroot user
   - Verifies no shell access
   - Tests help command

2. **integration-test** job (PRs only):
   - Sets up wallet with ethdo
   - Runs full Docker Compose stack
   - Verifies certificate loading
   - Tests metrics endpoint

## Troubleshooting

### Certificate errors

Ensure the signer certificate SAN matches the hostname used in docker-compose (`signer-test01`).

### Vouch fails to connect to Dirk

Check that:
- Dirk permissions grant access to `client-test01`
- CA certificate is shared between both services
- Network aliases are correctly configured

### Metrics not responding

Vouch needs a valid beacon node connection to fully start. Check:
- Lighthouse mock is healthy
- Vouch can reach `beacon-mock:5052`

### Healthcheck failures with "localhost"

In Alpine containers, `localhost` may resolve to IPv6 first. Use `127.0.0.1` explicitly in healthcheck commands.

### Dirk healthcheck issues

Dirk uses a distroless image without shell utilities. Don't use `nc` or other shell commands for healthchecks - use `service_started` dependency condition instead.

## Manual Testing

```bash
# View Vouch logs (look for "Starting dirk account manager")
docker logs -f vouch-test

# Check container user
docker inspect vouch-test --format='{{.Config.User}}'

# Verify Dirk connection via metrics
curl -s http://localhost:8081/metrics | grep dirk_server_connections
# Expected: dirk_server_connections{server="signer-test01:9091"} 1

# Check Dirk logs
docker logs dirk-test | grep "All services operational"

# Test mTLS connection manually (from external container)
docker run --rm --network docker_test-network \
  -v $(pwd)/../resources:/certs:ro \
  alpine/openssl s_client \
  -connect signer-test01:9091 \
  -cert /certs/client-test01.crt \
  -key /certs/client-test01.key \
  -CAfile /certs/Testing_certificate_authority.crt
```

## Files

```
testing/docker/
├── docker-compose.test.yml      # Main compose file
├── setup.sh                     # Wallet setup script
├── README.md                    # This file
└── configs/
    ├── dirk.json                # Dirk configuration
    ├── vouch-dirk.yml           # Vouch configuration
    ├── nginx-beacon-mock.conf   # Beacon mock nginx config
    └── beacon-responses/        # Mock API responses
        ├── config_spec.json
        ├── genesis.json
        └── fork_schedule.json
```
