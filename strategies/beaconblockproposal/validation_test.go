// Copyright © 2026 Attestant Limited.
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

package beaconblockproposal_test

import (
	"math"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/strategies/beaconblockproposal"
	"github.com/stretchr/testify/require"
)

type providerReadiness struct {
	ready    bool
	provider string
	slot     phase0.Slot
	index    phase0.ValidatorIndex
}

func (p *providerReadiness) ProviderReady(provider string, slot phase0.Slot, index phase0.ValidatorIndex) bool {
	p.provider = provider
	p.slot = slot
	p.index = index

	return p.ready
}

func gloasBlock(builderIndex gloas.BuilderIndex) *gloas.BeaconBlock {
	return &gloas.BeaconBlock{
		ProposerIndex: 7,
		Body: &gloas.BeaconBlockBody{
			SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
				Message: &gloas.ExecutionPayloadBid{BuilderIndex: builderIndex},
			},
		},
	}
}

func withoutPayload(builderIndex gloas.BuilderIndex) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{Version: spec.DataVersionGloas, Gloas: gloasBlock(builderIndex)}
}

func withPayload(builderIndex gloas.BuilderIndex) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		GloasContents:            &apiv1gloas.BlockContents{Block: gloasBlock(builderIndex)},
	}
}

func TestValidateBuilderBidReadiness(t *testing.T) {
	tests := []struct {
		name      string
		readiness *providerReadiness
		proposal  *api.VersionedEPBSProposal
		err       string
		checked   bool
	}{
		{
			name:     "NoReadiness",
			proposal: withoutPayload(1),
		},
		{
			name:      "NotGloas",
			readiness: &providerReadiness{},
			proposal:  &api.VersionedEPBSProposal{Version: spec.DataVersionFulu},
		},
		{
			name:      "SelfBuildUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(gloas.BuilderIndexSelfBuild),
		},
		{
			name:      "SelfBuildWithPayloadUnready",
			readiness: &providerReadiness{},
			proposal:  withPayload(gloas.BuilderIndexSelfBuild),
		},
		{
			name:      "BuilderReady",
			readiness: &providerReadiness{ready: true},
			proposal:  withoutPayload(1),
			checked:   true,
		},
		{
			name:      "BuilderUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(1),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
		{
			name:      "BuilderWithPayloadUnready",
			readiness: &providerReadiness{},
			proposal:  withPayload(1),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
		{
			name:      "BuilderBelowSelfBuildUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(gloas.BuilderIndex(math.MaxUint64 - 1)),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var readiness proposerpreferences.ProviderReadiness
			if test.readiness != nil {
				readiness = test.readiness
			}
			err := beaconblockproposal.ValidateBuilderBidReadiness(readiness, "node", 64, test.proposal)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			if test.checked {
				require.Equal(t, "node", test.readiness.provider)
				require.Equal(t, phase0.Slot(64), test.readiness.slot)
				require.Equal(t, phase0.ValidatorIndex(7), test.readiness.index)
			} else if test.readiness != nil {
				require.Empty(t, test.readiness.provider)
			}
		})
	}
}

func TestBuilderIndexSelfBuildIsUint64Max(t *testing.T) {
	require.Equal(t, gloas.BuilderIndex(math.MaxUint64), gloas.BuilderIndexSelfBuild)
}
