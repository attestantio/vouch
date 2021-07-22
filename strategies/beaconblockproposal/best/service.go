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

package best

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for beacon block proposals.
type Service struct {
	clientMonitor                metrics.ClientMonitor
	processConcurrency           int64
	beaconBlockProposalProviders map[string]eth2client.BeaconBlockProposalProvider
	signedBeaconBlockProvider    eth2client.SignedBeaconBlockProvider
	timeout                      time.Duration
}

// module-wide log.
var log zerolog.Logger

// New creates a new beacon block propsal strategy.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("strategy", "beaconblockproposal").Str("impl", "best").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		processConcurrency:           parameters.processConcurrency,
		beaconBlockProposalProviders: parameters.beaconBlockProposalProviders,
		signedBeaconBlockProvider:    parameters.signedBeaconBlockProvider,
		timeout:                      parameters.timeout,
		clientMonitor:                parameters.clientMonitor,
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	return s, nil
}
