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

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the manager for signers.
type Service struct {
	monitor                     metrics.SignerMonitor
	clientMonitor               metrics.ClientMonitor
	slotsPerEpoch               spec.Slot
	beaconProposerDomainType    spec.DomainType
	beaconAttesterDomainType    spec.DomainType
	randaoDomainType            spec.DomainType
	selectionProofDomainType    spec.DomainType
	aggregateAndProofDomainType spec.DomainType
	domainProvider              eth2client.DomainProvider
}

// module-wide log.
var log zerolog.Logger

// New creates a new dirk account manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "signer").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slots per epoch")
	}
	beaconAttesterDomainType, err := parameters.beaconAttesterDomainTypeProvider.BeaconAttesterDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain beacon attester domain type")
	}
	beaconProposerDomainType, err := parameters.beaconProposerDomainTypeProvider.BeaconProposerDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain beacon proposer domain type")
	}
	randaoDomainType, err := parameters.randaoDomainTypeProvider.RANDAODomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain RANDAO domain type")
	}
	selectionProofDomainType, err := parameters.selectionProofDomainTypeProvider.SelectionProofDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain selection proof domain type")
	}
	aggregateAndProofDomainType, err := parameters.aggregateAndProofDomainTypeProvider.AggregateAndProofDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain aggregate and proof domain type")
	}

	s := &Service{
		monitor:                     parameters.monitor,
		clientMonitor:               parameters.clientMonitor,
		slotsPerEpoch:               spec.Slot(slotsPerEpoch),
		beaconAttesterDomainType:    beaconAttesterDomainType,
		beaconProposerDomainType:    beaconProposerDomainType,
		randaoDomainType:            randaoDomainType,
		selectionProofDomainType:    selectionProofDomainType,
		aggregateAndProofDomainType: aggregateAndProofDomainType,
		domainProvider:              parameters.domainProvider,
	}

	return s, nil
}
