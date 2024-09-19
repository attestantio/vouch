// Copyright © 2024 Attestant Limited.
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

package mock

import (
	"context"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/blockrelay"
)

// BuilderBidProvider obtains a builder bid.
type BuilderBidProvider struct{}

// BuilderBid returns a builder bid.
func (BuilderBidProvider) BuilderBid(_ context.Context,
	_ phase0.Slot,
	_ phase0.Hash32,
	_ phase0.BLSPubKey,
	_ *beaconblockproposer.ProposerConfig,
	_ map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) (
	*blockauctioneer.Results,
	error,
) {
	return &blockauctioneer.Results{}, nil
}
