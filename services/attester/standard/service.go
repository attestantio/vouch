// Copyright © 2020 - 2023 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a beacon block attester.
type Service struct {
	log                        zerolog.Logger
	monitor                    metrics.Service
	processConcurrency         int64
	slotsPerEpoch              uint64
	chainTime                  chaintime.Service
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	attestationDataProvider    eth2client.AttestationDataProvider
	attestationsSubmitter      submitter.AttestationsSubmitter
	beaconAttestationsSigner   signer.BeaconAttestationsSigner
	attested                   map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}
	attestedMu                 sync.Mutex
	electraForkEpoch           phase0.Epoch
}

// New creates a new beacon block attester.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "attester").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	_, electraForkEpoch := electraDetails(ctx, log, parameters.specProvider)

	s := &Service{
		log:                        log,
		monitor:                    parameters.monitor,
		processConcurrency:         parameters.processConcurrency,
		slotsPerEpoch:              slotsPerEpoch,
		chainTime:                  parameters.chainTime,
		validatingAccountsProvider: parameters.validatingAccountsProvider,
		attestationDataProvider:    parameters.attestationDataProvider,
		attestationsSubmitter:      parameters.attestationsSubmitter,
		beaconAttestationsSigner:   parameters.beaconAttestationsSigner,
		attested:                   make(map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}),
		electraForkEpoch:           electraForkEpoch,
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	return s, nil
}

func electraDetails(ctx context.Context, log zerolog.Logger, specProvider eth2client.SpecProvider) (bool, phase0.Epoch) {
	// Fetch the electra fork epoch from the fork schedule.
	handlingElectra := true
	var electraForkEpoch phase0.Epoch
	electraForkEpoch, err := fetchElectraForkEpoch(ctx, specProvider)
	if err != nil {
		// Not handling electra after all.
		handlingElectra = false
		electraForkEpoch = 0xffffffffffffffff
	} else {
		log.Trace().Uint64("epoch", uint64(electraForkEpoch)).Msg("Obtained Electra fork epoch")
	}
	if !handlingElectra {
		log.Debug().Msg("Not handling Electra")
	}
	return handlingElectra, electraForkEpoch
}

// fetchElectraForkEpoch fetches the epoch for the electra hard fork.
func fetchElectraForkEpoch(ctx context.Context,
	specProvider eth2client.SpecProvider,
) (
	phase0.Epoch,
	error,
) {
	// Fetch the fork version.
	specResponse, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["ELECTRA_FORK_EPOCH"]
	if !exists {
		return 0, errors.New("electra fork version not known by chain")
	}
	epoch, isEpoch := tmp.(uint64)
	if !isEpoch {
		//nolint:revive
		return 0, errors.New("ELECTRA_FORK_EPOCH is not a uint64!")
	}

	return phase0.Epoch(epoch), nil
}
