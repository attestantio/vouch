# Vouch

[![Tag](https://img.shields.io/github/tag/attestantio/vouch.svg)](https://github.com/attestantio/vouch/releases/)
[![License](https://img.shields.io/github/license/attestantio/vouch.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/attestantio/vouch?status.svg)](https://godoc.org/github.com/attestantio/vouch)
![Lint](https://github.com/attestantio/vouch/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/attestantio/vouch)](https://goreportcard.com/report/github.com/attestantio/vouch)

An Ethereum 2 multi-node validator client.

## Table of Contents

- [Install](#install)
  - [Binaries](#binaries)
  - [Docker](#docker)
  - [Source](#source)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

### Binaries

Binaries for the latest version of Vouch can be obtained from [the releases page](https://github.com/attestantio/vouch/releases/latest).

### Docker

You can obtain the latest version of Vouch using docker with:

```
docker pull attestant/vouch
```

### Source

Vouch is a standard Go module which can be installed with:

```sh
go get github.com/attestantio/vouch
```

## Required beacon node parameters

### Prysm
Prysm must be started with the `--enable-debug-rpc-endpoints` option for Vouch to operate correctly.

## Usage
Vouch sits between the beacon node(s) and signer(s) in an Ethereum 2 validating infrastructure.  It runs as a standard daemon process.  The following documents provide information about configuring and using Vouch:

  - [Getting started](docs/getting_started.md) starting Vouch for the first time
  - [Prometheus metrics](docs/metrics/prometheus.md) Prometheus metrics
  - [Prometheus metrics](docs/metrics/grafana.md) Grafana dashboard for prometheus metrics
  - [Configuration](docs/configuration.md) Sample annotated configuration file
  - [Account manager](docs/accountmanager.md) Details of the supported account managers
  - [Execution configuration](docs/executionconfig.md) Details of the execution configuration
  - [Graffiti](docs/graffiti.md) Details of the graffiti provider

## Known issues

## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please see the [CONTRIBUTING.md](CONTRIBUTING.md) doc.

## License

[Apache-2.0](LICENSE) © 2020 Attestant Limited.
