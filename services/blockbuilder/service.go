// Copyright © 2022 Attestant Limited.
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

package blockbuilder

import (
	"context"

	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the block builder service.
type Service interface {
	// Name returns the name of the block builder.
	Name() string
}

// ValidatorRegistrationsSubmitter is the interface for a submitter of validator registrations.
type ValidatorRegistrationsSubmitter interface {
	// SubmitValidatorRegistrations submits validator registrations.
	SubmitValidatorRegistrations(ctx context.Context,
		accounts map[phase0.ValidatorIndex]e2wtypes.Account,
		feeRecipients map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
	) error
}

// BuilderBidProvider is the interface for a provider of builder bids.
type BuilderBidProvider interface {
	// BuilderBid obtains a builder bid.
	BuilderBid(ctx context.Context,
		slot phase0.Slot,
		parentHash phase0.Hash32,
		pubKey phase0.BLSPubKey,
	) (
		*spec.VersionedSignedBuilderBid,
		error,
	)
}
