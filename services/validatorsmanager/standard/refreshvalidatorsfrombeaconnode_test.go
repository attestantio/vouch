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

package standard_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/validatorsmanager/standard"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRefreshValidatorsFromBeaconNode(t *testing.T) {
	ctx := context.Background()
	s, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithClientMonitor(nullmetrics.New()),
		standard.WithFarFutureEpoch(phase0.Epoch(0xffffffffffffffff)),
		standard.WithValidatorsProvider(mock.NewValidatorsProvider()),
	)
	require.NoError(t, err)

	// Keys we want to fetch.
	fetchKeys := []phase0.BLSPubKey{
		testutil.HexToPubKey("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
		testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
		testutil.HexToPubKey("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
	}

	require.NoError(t, s.RefreshValidatorsFromBeaconNode(ctx, []phase0.BLSPubKey{
		testutil.HexToPubKey("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
		testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
	}))
	require.Len(t, s.ValidatorsByPubKey(ctx, fetchKeys), 2)

	require.NoError(t, s.RefreshValidatorsFromBeaconNode(ctx, []phase0.BLSPubKey{
		testutil.HexToPubKey("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
		testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
		testutil.HexToPubKey("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
	}))
	require.Len(t, s.ValidatorsByPubKey(ctx, fetchKeys), 3)

	require.NoError(t, s.RefreshValidatorsFromBeaconNode(ctx, []phase0.BLSPubKey{
		testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
		testutil.HexToPubKey("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
	}))
	require.Len(t, s.ValidatorsByPubKey(ctx, fetchKeys), 2)

	require.NoError(t, s.RefreshValidatorsFromBeaconNode(ctx, []phase0.BLSPubKey{
		testutil.HexToPubKey("0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7"),
		testutil.HexToPubKey("0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a"),
		testutil.HexToPubKey("0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268"),
	}))
	require.Len(t, s.ValidatorsByPubKey(ctx, fetchKeys), 0)
}
