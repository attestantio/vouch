module github.com/attestantio/vouch

go 1.14

require (
	cloud.google.com/go v0.66.0 // indirect
	github.com/OneOfOne/xxhash v1.2.5 // indirect
	github.com/attestantio/go-eth2-client v0.6.4
	github.com/aws/aws-sdk-go v1.34.31
	github.com/ferranbt/fastssz v0.0.0-20200826142241-3a913c5a1313
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.15.0 // indirect
	github.com/herumi/bls-eth-go-binary v0.0.0-20200923072303-32b29e5d8cbf
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/minio/highwayhash v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.14.0 // indirect
	github.com/prometheus/procfs v0.2.0 // indirect
	github.com/prysmaticlabs/ethereumapis v0.0.0-20200923224139-64c46fb1b0fa
	github.com/prysmaticlabs/go-bitfield v0.0.0-20200618145306-2ae0807bef65
	github.com/rs/zerolog v1.20.0
	github.com/sasha-s/go-deadlock v0.2.0
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.4.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	github.com/uber/jaeger-lib v2.3.0+incompatible // indirect
	github.com/wealdtech/go-bytesutil v1.1.1
	github.com/wealdtech/go-eth2-types/v2 v2.5.0
	github.com/wealdtech/go-eth2-wallet v1.14.0
	github.com/wealdtech/go-eth2-wallet-dirk v1.0.3
	github.com/wealdtech/go-eth2-wallet-store-filesystem v1.16.1
	github.com/wealdtech/go-eth2-wallet-types/v2 v2.7.0
	github.com/wealdtech/go-majordomo v1.0.1
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/net v0.0.0-20200925080053-05aa5d4ee321 // indirect
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/sys v0.0.0-20200923182605-d9f96fdee20d // indirect
	google.golang.org/api v0.32.0 // indirect
	google.golang.org/genproto v0.0.0-20200925023002-c2d885f95484 // indirect
	google.golang.org/grpc v1.32.0
	gopkg.in/ini.v1 v1.61.0 // indirect
)

replace github.com/attestantio/go-eth2-client => ../go-eth2-client
