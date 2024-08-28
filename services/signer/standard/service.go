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
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the manager for signers.
type Service struct {
	monitor                               metrics.SignerMonitor
	slotsPerEpoch                         phase0.Slot
	beaconProposerDomainType              phase0.DomainType
	beaconAttesterDomainType              phase0.DomainType
	randaoDomainType                      phase0.DomainType
	selectionProofDomainType              phase0.DomainType
	aggregateAndProofDomainType           phase0.DomainType
	syncCommitteeDomainType               *phase0.DomainType
	syncCommitteeSelectionProofDomainType *phase0.DomainType
	contributionAndProofDomainType        *phase0.DomainType
	applicationBuilderDomainType          *phase0.DomainType
	blobSidecarDomainType                 *phase0.DomainType
	domainProvider                        eth2client.DomainProvider
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

	beaconAttesterDomainType, err := domainType(spec, "DOMAIN_BEACON_ATTESTER")
	if err != nil {
		return nil, err
	}

	beaconProposerDomainType, err := domainType(spec, "DOMAIN_BEACON_PROPOSER")
	if err != nil {
		return nil, err
	}

	randaoDomainType, err := domainType(spec, "DOMAIN_RANDAO")
	if err != nil {
		return nil, err
	}

	selectionProofDomainType, err := domainType(spec, "DOMAIN_SELECTION_PROOF")
	if err != nil {
		return nil, err
	}

	aggregateAndProofDomainType, err := domainType(spec, "DOMAIN_AGGREGATE_AND_PROOF")
	if err != nil {
		return nil, err
	}

	// The following are optional.
	var syncCommitteeDomainType *phase0.DomainType
	if tmp, err := domainType(spec, "DOMAIN_SYNC_COMMITTEE"); err == nil {
		syncCommitteeDomainType = &tmp
	}

	var syncCommitteeSelectionProofDomainType *phase0.DomainType
	if tmp, err := domainType(spec, "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"); err == nil {
		syncCommitteeSelectionProofDomainType = &tmp
	}

	var contributionAndProofDomainType *phase0.DomainType
	if tmp, err := domainType(spec, "DOMAIN_CONTRIBUTION_AND_PROOF"); err == nil {
		contributionAndProofDomainType = &tmp
	}

	var applicationBuilderDomainType *phase0.DomainType
	if tmp, err := domainType(spec, "DOMAIN_APPLICATION_BUILDER"); err == nil {
		applicationBuilderDomainType = &tmp
	}

	var blobSidecarDomainType *phase0.DomainType
	if tmp, err := domainType(spec, "DOMAIN_BLOB_SIDECAR"); err == nil {
		blobSidecarDomainType = &tmp
	}

	s := &Service{
		monitor:                               parameters.monitor,
		slotsPerEpoch:                         phase0.Slot(slotsPerEpoch),
		beaconAttesterDomainType:              beaconAttesterDomainType,
		beaconProposerDomainType:              beaconProposerDomainType,
		randaoDomainType:                      randaoDomainType,
		selectionProofDomainType:              selectionProofDomainType,
		aggregateAndProofDomainType:           aggregateAndProofDomainType,
		syncCommitteeDomainType:               syncCommitteeDomainType,
		syncCommitteeSelectionProofDomainType: syncCommitteeSelectionProofDomainType,
		contributionAndProofDomainType:        contributionAndProofDomainType,
		applicationBuilderDomainType:          applicationBuilderDomainType,
		blobSidecarDomainType:                 blobSidecarDomainType,
		domainProvider:                        parameters.domainProvider,
	}

	return s, nil
}

func domainType(spec map[string]interface{}, input string) (phase0.DomainType, error) {
	tmp, exists := spec[input]
	if !exists {
		return phase0.DomainType{}, fmt.Errorf("%v not found in spec", input)
	}
	domainType, ok := tmp.(phase0.DomainType)
	if !ok {
		return phase0.DomainType{}, fmt.Errorf("%v of unexpected type", input)
	}
	return domainType, nil
}
