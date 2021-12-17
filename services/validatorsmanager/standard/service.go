// Copyright © 2020 Attestant Limited.
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

package standard

import (
	"context"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the manager for validators.
type Service struct {
	monitor            metrics.ValidatorsManagerMonitor
	clientMonitor      metrics.ClientMonitor
	validatorsProvider eth2client.ValidatorsProvider
	farFutureEpoch     phase0.Epoch

	validatorsMutex        sync.RWMutex
	validatorsByIndex      map[phase0.ValidatorIndex]*phase0.Validator
	validatorsByPubKey     map[phase0.BLSPubKey]*phase0.Validator
	validatorPubKeyToIndex map[phase0.BLSPubKey]phase0.ValidatorIndex
}

// module-wide log.
var log zerolog.Logger

// New creates a new validator provider.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "validatorsmanager").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:                parameters.monitor,
		clientMonitor:          parameters.clientMonitor,
		farFutureEpoch:         parameters.farFutureEpoch,
		validatorsProvider:     parameters.validatorsProvider,
		validatorsByIndex:      make(map[phase0.ValidatorIndex]*phase0.Validator),
		validatorsByPubKey:     make(map[phase0.BLSPubKey]*phase0.Validator),
		validatorPubKeyToIndex: make(map[phase0.BLSPubKey]phase0.ValidatorIndex),
	}

	return s, nil
}
