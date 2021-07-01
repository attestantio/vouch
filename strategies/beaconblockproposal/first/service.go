// Copyright © 2020 Attestant Limited.
// Licensed )junder the Apache License, Version 2.0 (the "License");
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

package first

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for beacon block proposals.
type Service struct {
	clientMonitor                metrics.ClientMonitor
	beaconBlockProposalProviders map[string]eth2client.BeaconBlockProposalProvider
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
	log = zerologger.With().Str("strategy", "beaconblockproposal").Str("impl", "first").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		beaconBlockProposalProviders: parameters.beaconBlockProposalProviders,
		timeout:                      parameters.timeout,
		clientMonitor:                parameters.clientMonitor,
	}

	return s, nil
}

// BeaconBlockProposal provides the first beacon block proposal from a number of beacon nodes.
func (s *Service) BeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	// We create a cancelable context with a timeout.  As soon as the first provider has responded we
	// cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	proposalCh := make(chan *spec.VersionedBeaconBlock, 1)
	for name, provider := range s.beaconBlockProposalProviders {
		go func(ctx context.Context, name string, provider eth2client.BeaconBlockProposalProvider, ch chan *spec.VersionedBeaconBlock) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(slot)).Logger()

			started := time.Now()
			proposal, err := provider.BeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
			s.clientMonitor.ClientOperation(name, "beacon block proposal", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain beacon block proposal")
				return
			}
			if proposal == nil {
				log.Warn().Err(err).Msg("Returned empty beacon block proposal")
				return
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block proposal")

			ch <- proposal
		}(ctx, name, provider, proposalCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain beacon block proposal before timeout")
		return nil, errors.New("failed to obtain beacon block proposal before timeout")
	case proposal := <-proposalCh:
		cancel()
		return proposal, nil
	}
}
