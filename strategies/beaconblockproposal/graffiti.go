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

package beaconblockproposal

import (
	"bytes"
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
)

// GraffitiForProvider expands the client placeholder for a proposal provider.
func GraffitiForProvider(ctx context.Context,
	provider eth2client.MultiForkProposalProvider,
	graffiti [32]byte,
) (
	[32]byte,
	error,
) {
	providerGraffiti := graffiti[:]
	if !bytes.Contains(providerGraffiti, []byte("{{CLIENT}}")) {
		return graffiti, nil
	}

	nodeClientProvider, isProvider := provider.(eth2client.NodeClientProvider)
	if !isProvider {
		return graffiti, nil
	}
	nodeClientResponse, err := nodeClientProvider.NodeClient(ctx)
	if err != nil {
		return graffiti, err
	}

	providerGraffiti = bytes.ReplaceAll(providerGraffiti, []byte("{{CLIENT}}"), []byte(nodeClientResponse.Data))
	if len(providerGraffiti) > len(graffiti) {
		providerGraffiti = providerGraffiti[:len(graffiti)]
	}
	var res [32]byte
	copy(res[:], providerGraffiti)

	return res, nil
}
