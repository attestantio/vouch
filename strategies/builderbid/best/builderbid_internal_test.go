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

package best

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func pubkey(input string) *phase0.BLSPubKey {
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var key phase0.BLSPubKey
	copy(key[:], data)
	return &key
}

func domain(input string) phase0.Domain {
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var domain phase0.Domain
	copy(domain[:], data)
	return domain
}

func TestVerifyBidSignature(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, e2types.InitBLS())

	s := &Service{
		relayPubkeys:             make(map[phase0.BLSPubKey]*e2types.BLSPublicKey),
		applicationBuilderDomain: domain("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"),
	}

	tests := []struct {
		name        string
		bid         []byte
		relayConfig *beaconblockproposer.RelayConfig
		provider    builderclient.BuilderBidProvider
		expected    bool
		err         string
	}{
		{
			name:        "NoBuilderPubkey",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0x877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74191"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider:    &mock.BuilderClient{},
			expected:    true,
		},
		{
			name:        "Good",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0x877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74191"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider: &mock.BuilderClient{
				MockPubkey: pubkey("0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"),
			},
			expected: true,
		},
		{
			name:        "WrongSignature",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0xa73233d802d26e59489bc8d67b56465b0807e90a3a2e457c500a3f612e46d302d5b0a1c02dc2f51a11747ab0bb129ef416bee4e74b3710052f366ce2200cdc56fcf69ca68476874d4a2c8dc7afde78ff93e3e7f145e742d1abb800c3b11327b5"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider: &mock.BuilderClient{
				MockPubkey: pubkey("0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"),
			},
			expected: false,
		},
		{
			name:        "InvalidSignature",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0x877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74190"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider: &mock.BuilderClient{
				MockPubkey: pubkey("0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"),
			},
			err: "invalid signature: failed to deserialize signature: err blsSignatureDeserialize 877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74190",
		},
		{
			name:        "WrongKey",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0x877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74191"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider: &mock.BuilderClient{
				MockPubkey: pubkey("0x821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff516"),
			},
			expected: false,
		},
		{
			name:        "InvalidKey",
			bid:         []byte(`{"version":"BELLATRIX","data":{"message":{"header":{"parent_hash":"0x15b38d69d54789359784bd2826d2811e938e6abf87588ab75d0e62857494771a","fee_recipient":"0x320715b08bcf4cac1df2c55288a6bad79da1566b","state_root":"0xa47d81eb2717c3e2ae136e82e1242c4b350cda041f189aac422a16a9a7c6fca5","receipts_root":"0xd080a066ff223b1c759709fa9cd8d9105952cb7a5b231beafe683f964e2ab0d4","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x924ac8e956cf60a79b10ed4087c4678862eae91c0c9c50c768eeb3ee852786de","block_number":"2229624","gas_limit":"30000000","gas_used":"42000","timestamp":"1667652084","extra_data":"0x496c6c756d696e61746520446d6f63726174697a6520447374726962757465","base_fee_per_gas":"7","block_hash":"0xf843fff3b010a668e97a7958a1fab678ce34b06dc394452df17dad43a0f8a9ad","transactions_root":"0x6febb1545754c4ebcf3335dad815f2380289156ef264f72a69260535cdcad4e8"},"value":"52499999853000","pubkey":"0x845bd072b7cd566f02faeb0a4033ce9399e42839ced64e8b2adcfc859ed1e8e1a5a293336a49feac6d9a5edb779be53a"},"signature":"0x877681cc963750f3b63968baded23994f4e460b8b38a9ea11ba4c2fe0aba6c3902004248ac61c914092641b743fff44303ddff9e82be46da780ebff0fa777867424dc8e3b5bfe2b2484651dab270676cd4edf105508651cbd62f544f53b74191"}}`),
			relayConfig: &beaconblockproposer.RelayConfig{},
			provider: &mock.BuilderClient{
				MockPubkey: pubkey("0x821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff515"),
			},
			err: "invalid public key supplied with bid: failed to deserialize public key: err blsPublicKeyDeserialize 821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff515",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bid := &builderspec.VersionedSignedBuilderBid{}
			require.NoError(t, json.Unmarshal(test.bid, bid))
			verified, err := s.verifyBidSignature(ctx, test.relayConfig, bid, test.provider)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, verified)
			}
		})
	}
}
