module github.com/attestantio/vouch

go 1.16

require (
	github.com/attestantio/go-eth2-client v0.8.2
	github.com/aws/aws-sdk-go v1.42.23
	github.com/cncf/xds/go v0.0.0-20211215212155-112fc4fa679d // indirect
	github.com/herumi/bls-eth-go-binary v0.0.0-20211122012301-02ac68186ac0 // indirect
	github.com/jackc/puddle v1.2.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.0
	github.com/prysmaticlabs/go-bitfield v0.0.0-20210809151128-385d8c5e3fb7
	github.com/r3labs/sse/v2 v2.7.3 // indirect
	github.com/rs/zerolog v1.26.0
	github.com/sasha-s/go-deadlock v0.3.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.0
	github.com/uber/jaeger-client-go v2.30.0+incompatible
	github.com/wealdtech/go-bytesutil v1.1.1
	github.com/wealdtech/go-eth2-types/v2 v2.6.0
	github.com/wealdtech/go-eth2-wallet v1.15.0
	github.com/wealdtech/go-eth2-wallet-dirk v1.2.0
	github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 v1.2.0
	github.com/wealdtech/go-eth2-wallet-hd/v2 v2.6.0
	github.com/wealdtech/go-eth2-wallet-store-filesystem v1.17.0
	github.com/wealdtech/go-eth2-wallet-store-scratch v1.7.0
	github.com/wealdtech/go-eth2-wallet-types/v2 v2.9.0
	github.com/wealdtech/go-majordomo v1.0.1
	go.uber.org/atomic v1.9.0
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/net v0.0.0-20211215060638-4ddde0e984e9 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211215211219-4abf325e0275 // indirect
	google.golang.org/grpc v1.43.0
	gotest.tools v2.2.0+incompatible
)

replace github.com/attestantio/go-eth2-client => ../go-eth2-client
