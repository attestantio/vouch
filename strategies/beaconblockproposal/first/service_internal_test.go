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

package first

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestFirstProposalRetainsQueuedErrorsAtTimeout(t *testing.T) {
	firstErr := errors.New("first proposal failed")
	secondErr := errors.New("second proposal failed")

	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan *proposalResult[int], 2)
		results <- &proposalResult[int]{provider: "one", err: firstErr}
		results <- &proposalResult[int]{provider: "two", err: secondErr}
		cancel()

		_, err := firstProposal(ctx,
			zerolog.Nop(),
			results,
			2,
			nil,
			"failed to obtain proposal",
			"Failed to obtain proposal before timeout",
		)
		require.ErrorIs(t, err, firstErr)
		require.ErrorIs(t, err, secondErr)
	}
}
