// Copyright © 2023 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package best

import (
	"context"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// Service is the provider for builder bids.
type Service struct {
	log                      zerolog.Logger
	monitor                  metrics.Service
	chainTime                chaintime.Service
	blockGasLimitProvider    cache.BlockGasLimitProvider
	timeout                  time.Duration
	releaseVersion           string
	relayPubkeys             map[phase0.BLSPubKey]*e2types.BLSPublicKey
	relayPubkeysMu           sync.RWMutex
	applicationBuilderDomain phase0.Domain
}

// New creates a new builder bid strategy.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("strategy", "builderbid").Str("impl", "best").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	// The application domain is static, so fetch it here once.
	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data
	tmp, exists := spec["DOMAIN_APPLICATION_BUILDER"]
	if !exists {
		return nil, errors.New("failed to obtain application builder domain type")
	}
	applicationBuilderDomainType, ok := tmp.(phase0.DomainType)
	if !ok {
		return nil, errors.New("unexpected type for application builder domain type")
	}
	domain, err := parameters.domainProvider.GenesisDomain(ctx, applicationBuilderDomainType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain application builder domain")
	}

	s := &Service{
		log:                      log,
		monitor:                  parameters.monitor,
		chainTime:                parameters.chainTime,
		blockGasLimitProvider:    parameters.blockGasLimitProvider,
		timeout:                  parameters.timeout,
		releaseVersion:           parameters.releaseVersion,
		relayPubkeys:             make(map[phase0.BLSPubKey]*e2types.BLSPublicKey),
		applicationBuilderDomain: domain,
	}

	return s, nil
}
