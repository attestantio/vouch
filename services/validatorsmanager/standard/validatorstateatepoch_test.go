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

	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/validatorsmanager/standard"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestValidatorStateAtEpoch(t *testing.T) {
	ctx := context.Background()
	s, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New(context.Background())),
		standard.WithClientMonitor(nullmetrics.New(context.Background())),
		standard.WithFarFutureEpoch(spec.Epoch(0xffffffffffffffff)),
		standard.WithValidatorsProvider(mock.NewValidatorsProvider()),
	)
	require.NoError(t, err)
	require.NoError(t, s.RefreshValidatorsFromBeaconNode(ctx, []spec.BLSPubKey{
		testutil.HexToPubKey("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
		testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
		testutil.HexToPubKey("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
		testutil.HexToPubKey("0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e"),
		testutil.HexToPubKey("0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e"),
		testutil.HexToPubKey("0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34"),
		testutil.HexToPubKey("0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373"),
		testutil.HexToPubKey("0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac"),
		testutil.HexToPubKey("0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7"),
		testutil.HexToPubKey("0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a"),
		testutil.HexToPubKey("0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268"),
		testutil.HexToPubKey("0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d"),
		testutil.HexToPubKey("0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327"),
		testutil.HexToPubKey("0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c"),
		testutil.HexToPubKey("0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f"),
		testutil.HexToPubKey("0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f"),
		testutil.HexToPubKey("0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7"),
		testutil.HexToPubKey("0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f"),
		testutil.HexToPubKey("0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9"),
		testutil.HexToPubKey("0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e"),
		testutil.HexToPubKey("0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc"),
		testutil.HexToPubKey("0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d"),
		testutil.HexToPubKey("0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c"),
		testutil.HexToPubKey("0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191"),
		testutil.HexToPubKey("0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4"),
		testutil.HexToPubKey("0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021"),
		testutil.HexToPubKey("0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104"),
		testutil.HexToPubKey("0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879"),
		testutil.HexToPubKey("0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8"),
		testutil.HexToPubKey("0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99"),
		testutil.HexToPubKey("0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260"),
		testutil.HexToPubKey("0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d"),
	}))

	tests := []struct {
		name           string
		validatorIndex spec.ValidatorIndex
		epoch          spec.Epoch
		state          api.ValidatorState
		err            string
	}{
		{
			name:           "Good",
			validatorIndex: 1,
			epoch:          0,
			state:          api.ValidatorStateActiveOngoing,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := s.ValidatorStateAtEpoch(ctx, test.validatorIndex, test.epoch)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.state, state)
			}
		})
	}
}
