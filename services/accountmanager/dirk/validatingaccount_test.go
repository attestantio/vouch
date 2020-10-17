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

package dirk_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/attestantio/dirk/testing/daemon"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/accountmanager/dirk"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/resources"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPubKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			provider, isProvider := account.(accountmanager.ValidatingAccountPubKeyProvider)
			require.True(t, isProvider)
			res, err := provider.PubKey(ctx)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected api.ValidatorState
	}{
		{
			name:     "0",
			index:    0,
			expected: api.ValidatorStateActiveOngoing,
		},
		{
			name:     "1",
			index:    1,
			expected: api.ValidatorStateActiveOngoing,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			provider, isProvider := account.(accountmanager.ValidatingAccountStateProvider)
			require.True(t, isProvider)
			res := provider.State()
			require.Equal(t, test.expected, res)
		})
	}
}

func TestSignSlotSelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0xa207bbed7d1e43585e5d42e3f09a5179f21a12a33b66ac9af47132c20f9b7b7caaa162420e095664ca3318fe365776e80bd0f9ef1e3b07a2e5340d0c07152234bf18f7596c8d94d72e11961ad8455f08c4417b0019246e24f570a166f86de2c5"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0xa17b1a6decb1503b5b8eacb4ca48e2f1665e43c587088995bb7e2da0738268ad0e1f28519ed79fbb318b9b98c6e8b65805a005bca4c98656fefb9ec6753df29ad6ef92da5e3074c027caaaf738d37fd09e08d8d8f86531bd80cf4152709240f9"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			signer, isSigner := account.(accountmanager.SlotSelectionSigner)
			require.True(t, isSigner)
			res, err := signer.SignSlotSelection(ctx, 0)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestSignRANDAOReveal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0xb990eeca35dadda689f5561ac39bba9a27a0c41c40bd1ce584595ba2a44782a89e2630ced7b1fc348b2408d15fa6746c177c5227625e39031e6be1536387ae33e21ec3de6d1d0b46bada1b99b621f8d40eab81882400c028716b22d31999b177"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0x840c144974632f09084b91ec7be5044c3fe9dd0dc7ce1031c0c78911807e264f36cb4fee0ddccf0ca93bada5d102cfb7118e6b75b5ecc5e18648a29f21f70727f3587b8d34bc7474d926fab4fb30eae4436153c336e6eb290d3d1cdd88ee9a58"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			signer, isSigner := account.(accountmanager.RANDAORevealSigner)
			require.True(t, isSigner)
			res, err := signer.SignRANDAOReveal(ctx, 0)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestSignBeaconBlockProposal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0x83d91f4fe6dd962493f212a94dc62c81358ffbdb6c3f8567d96fbe31c5ab505db1a3d37b8c3d653225621bb34918d30b069bbc02daeea9e1b2e62166014563f271fdfbe9aad37f0d155754f63eb368dd853c0bf723ad64af371a04b7778e891a"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0x9176ac06d426beb74bfb3969a619d364a5e214f0da511433b56f8dca47b93725c4ddd225c1cb81dd5a26fc321801a1d70b1c28c6cf705c010fadf9c4f139c044224680d8c60e425c9d6e6b8e8af21f12cffab38b393a9b7529527b92cf20e80a"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			signer, isSigner := account.(accountmanager.BeaconBlockSigner)
			require.True(t, isSigner)
			res, err := signer.SignBeaconBlockProposal(ctx,
				1,
				1,
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
			)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestBeaconAttestationsSigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0x974fb6782c196c8e523b74ea3dbdfe7b122c6a18590992f2cb789358dcea6c28498ffa6cac68629bf83175cb55bb0d3910919eab48d2934c3a81655dcc27c91a996ca4a9880ffde7864f6aba3cd7c40111e3317c817032776d077d8d6a348bb2"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0x84a1c3c50d093901ea1b027b18598e4b9cf0f848f6bd49f2807a3f6ea37c0cbf3794556705863de0ae8ea7dd2da4d4d91436e2ca96fa1eb045a22fb7704cedf8a842fa881a416eaa02444454d9f7f8040b84fc3cd3d42817f6992c3c29e16007"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			signer, isSigner := account.(accountmanager.BeaconAttestationSigner)
			require.True(t, isSigner)
			res, err := signer.SignBeaconAttestation(ctx,
				1,
				1,
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
				0,
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
				1,
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
			)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestAggregateAndProofsigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	s, err := dirk.New(context.Background(),
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New(context.Background())),
		dirk.WithClientMonitor(nullmetrics.New(context.Background())),
		dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		dirk.WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
		dirk.WithClientKey([]byte(resources.ClientTest01Key)),
		dirk.WithCACert([]byte(resources.CACrt)),
		dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
		dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		dirk.WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.Nil(t, err)

	tests := []struct {
		name     string
		index    uint64
		expected []byte
	}{
		{
			name:     "0",
			index:    0,
			expected: _byte("0xafd6b2ed80506b63e964820aba6523735d6156d4f2e3d53c88075f22b2a48447d6f083952e7d6c315a96dfde35b6959616591ac9d8b2d7f1c423b7f257e6f5eb4406b97b55270a9101cca809e76c7759aaf1235b028aa23da118697dfb9c34c5"),
		},
		{
			name:     "1",
			index:    1,
			expected: _byte("0xa006085be92bb0ee2cf2bba3da0d5e21630efb7e32a5e4fa7ca742ea0bd273f76a6336ef3a9817200bddbc0b4a6dbecf1303d9804806fa38ee05b7d5cfbba6e851c37ca587d66df935c296e6210db69f8b4c96f5e590cb83c7f82c06aee1d4c3"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := s.AccountsByIndex(ctx, []uint64{test.index})
			require.NoError(t, err)
			require.Equal(t, 1, len(accounts))
			account := accounts[0]

			signer, isSigner := account.(accountmanager.AggregateAndProofSigner)
			require.True(t, isSigner)
			res, err := signer.SignAggregateAndProof(ctx,
				1,
				_byte("0x0000000000000000000000000000000000000000000000000000000000000000"),
			)
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}
