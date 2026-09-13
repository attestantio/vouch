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

package standard

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

func (s *Service) builderConfig(ctx context.Context, duty *beaconblockproposer.Duty) (*gloas.BuilderConfig, bellatrix.ExecutionAddress, error) {
	feeRecipient := bellatrix.ExecutionAddress{}
	resolved := &beaconblockproposer.EPBSBuilderConfig{
		BuilderBoostFactor: 100,
		Builders:           make([]*beaconblockproposer.EPBSBuilder, 0),
	}
	if s.executionConfigProvider != nil {
		proposerConfig, err := s.executionConfigProvider.ProposerConfig(ctx, duty.Account(), util.ValidatorPubkey(duty.Account()))
		if err != nil {
			return nil, bellatrix.ExecutionAddress{}, errors.Wrap(err, "failed to obtain ePBS builder configuration")
		}
		if proposerConfig != nil {
			feeRecipient = proposerConfig.FeeRecipient
			if proposerConfig.EPBSBuilderConfig != nil {
				resolved = proposerConfig.EPBSBuilderConfig
			}
		}
	}

	config := &gloas.BuilderConfig{
		MinBid:             resolved.MinBid,
		BuilderBoostFactor: resolved.BuilderBoostFactor,
		Builders:           make([]*gloas.BuilderEntry, len(resolved.Builders)),
	}
	for i, builder := range resolved.Builders {
		if builder == nil {
			return nil, bellatrix.ExecutionAddress{}, errors.Errorf("direct builder %d is missing", i)
		}
		if s.builderRequestAuthSigner == nil {
			return nil, bellatrix.ExecutionAddress{}, errors.New("no builder request authorization signer available")
		}
		auth := &gloas.BuilderRequestAuth{
			Data: append([]byte(nil), builder.AuthData...),
			Slot: duty.Slot(),
		}
		signature, err := s.builderRequestAuthSigner.SignBuilderRequestAuth(ctx, duty.Account(), auth)
		if err != nil {
			return nil, bellatrix.ExecutionAddress{}, errors.New("failed to sign direct-builder request authorization")
		}
		config.Builders[i] = &gloas.BuilderEntry{
			URL: append([]byte(nil), []byte(builder.URL)...),
			Auth: &gloas.SignedBuilderRequestAuth{
				Message:   auth,
				Signature: signature,
			},
			BuilderPubkeys:      append([]phase0.BLSPubKey(nil), builder.BuilderPubkeys...),
			MaxExecutionPayment: builder.MaxExecutionPayment,
			MinBid:              builder.MinBid,
			BuilderBoostFactor:  builder.BuilderBoostFactor,
		}
	}

	return config, feeRecipient, nil
}
