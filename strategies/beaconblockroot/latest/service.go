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

package latest

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/cache"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for beacon block roots.
type Service struct {
	log                      zerolog.Logger
	processConcurrency       int64
	beaconBlockRootProviders map[string]eth2client.BeaconBlockRootProvider
	timeout                  time.Duration
	blockRootToSlotCache     cache.BlockRootToSlotProvider
}

// New creates a new attestation data strategy.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("strategy", "beaconblockroot").Str("impl", "latest").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:                      log,
		timeout:                  parameters.timeout,
		processConcurrency:       parameters.processConcurrency,
		beaconBlockRootProviders: parameters.beaconBlockRootProviders,
		blockRootToSlotCache:     parameters.blockRootToSlotCache,
	}
	s.log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	return s, nil
}
