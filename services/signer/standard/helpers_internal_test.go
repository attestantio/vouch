// Copyright © 2020 - 2026 Attestant Limited.
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
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// mockSignature implements e2types.Signature for testing.
type mockSignature struct {
	data []byte
}

func (s *mockSignature) Marshal() []byte                                       { return s.data }
func (*mockSignature) Verify(_ []byte, _ e2types.PublicKey) bool               { return true }
func (*mockSignature) VerifyAggregate(_ [][]byte, _ []e2types.PublicKey) bool   { return true }
func (*mockSignature) VerifyAggregateCommon(_ []byte, _ []e2types.PublicKey) bool { return true }

// mockPublicKey implements e2types.PublicKey for testing.
type mockPublicKey struct {
	data []byte
}

func (k *mockPublicKey) Marshal() []byte            { return k.data }
func (k *mockPublicKey) Copy() e2types.PublicKey     { return k }
func (*mockPublicKey) Aggregate(_ e2types.PublicKey) {}

// mockSignerAccount implements e2wtypes.Account and e2wtypes.AccountSigner.
type mockSignerAccount struct {
	id        uuid.UUID
	name      string
	pubKey    *mockPublicKey
	signCount int
}

func (a *mockSignerAccount) ID() uuid.UUID             { return a.id }
func (a *mockSignerAccount) Name() string               { return a.name }
func (a *mockSignerAccount) PublicKey() e2types.PublicKey { return a.pubKey }
func (a *mockSignerAccount) Sign(_ context.Context, data []byte) (e2types.Signature, error) {
	a.signCount++
	// Return deterministic signature based on account name + data.
	sigData := make([]byte, 96)
	copy(sigData, append([]byte(a.name+":"), data[:8]...))

	return &mockSignature{data: sigData}, nil
}

// Compile-time interface checks.
var (
	_ e2wtypes.Account       = (*mockSignerAccount)(nil)
	_ e2wtypes.AccountSigner = (*mockSignerAccount)(nil)
)

// batchRecord records one SignGenericMulti call for verification.
type batchRecord struct {
	accountIDs []uuid.UUID
	data       [][]byte
}

// mockMultiSignerAccount implements Account and AccountProtectingMultiSigner.
// All instances sharing the same *batches pointer record calls to SignGenericMulti.
type mockMultiSignerAccount struct {
	id           uuid.UUID
	name         string
	pubKey       *mockPublicKey
	batches      *[]batchRecord
	failOnBatch  *int // if non-nil, SignGenericMulti returns error when len(*batches) == *failOnBatch
}

func (a *mockMultiSignerAccount) ID() uuid.UUID               { return a.id }
func (a *mockMultiSignerAccount) Name() string                 { return a.name }
func (a *mockMultiSignerAccount) PublicKey() e2types.PublicKey  { return a.pubKey }

func (a *mockMultiSignerAccount) SignBeaconAttestations(_ context.Context,
	_ uint64,
	_ []e2wtypes.Account,
	_ []uint64,
	_ []byte,
	_ uint64,
	_ []byte,
	_ uint64,
	_ []byte,
	_ []byte,
) ([]e2types.Signature, error) {
	return nil, errors.New("not implemented")
}

func (a *mockMultiSignerAccount) SignGenericMulti(_ context.Context,
	accounts []e2wtypes.Account,
	data [][]byte,
	_ []byte,
) ([]e2types.Signature, error) {
	if a.failOnBatch != nil && len(*a.batches) == *a.failOnBatch {
		return nil, errors.New("signing failed")
	}

	ids := make([]uuid.UUID, len(accounts))
	for i, acct := range accounts {
		ids[i] = acct.ID()
	}
	dataCopy := make([][]byte, len(data))
	for i, d := range data {
		dataCopy[i] = make([]byte, len(d))
		copy(dataCopy[i], d)
	}
	*a.batches = append(*a.batches, batchRecord{accountIDs: ids, data: dataCopy})

	sigs := make([]e2types.Signature, len(accounts))
	for i, acct := range accounts {
		sigData := make([]byte, 96)
		copy(sigData, append([]byte(acct.Name()+":"), data[i][:8]...))
		sigs[i] = &mockSignature{data: sigData}
	}

	return sigs, nil
}

// Compile-time interface checks for multi-signer mock.
var (
	_ e2wtypes.Account                       = (*mockMultiSignerAccount)(nil)
	_ e2wtypes.AccountProtectingMultiSigner  = (*mockMultiSignerAccount)(nil)
)

func newMockMultiSignerAccount(name string, batches *[]batchRecord) *mockMultiSignerAccount {
	return &mockMultiSignerAccount{
		id:      uuid.New(),
		name:    name,
		pubKey:  &mockPublicKey{data: []byte(name)},
		batches: batches,
	}
}

func newMockAccount(name string) *mockSignerAccount {
	return &mockSignerAccount{
		id:     uuid.New(),
		name:   name,
		pubKey: &mockPublicKey{data: []byte(name)},
	}
}

func TestSignRootsMultiBatchSplitting(t *testing.T) {
	rootA := phase0.Root{0x01}
	rootB := phase0.Root{0x02}
	rootC := phase0.Root{0x03}
	domain := phase0.Domain{0xAA}

	tests := []struct {
		name            string
		accounts        []*mockMultiSignerAccount
		roots           []phase0.Root
		expectedBatches int // number of SignGenericMulti calls
		err             string
	}{
		{
			name: "SingleAccount_NoBatchSplit",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				return []*mockMultiSignerAccount{newMockMultiSignerAccount("acct-1", batches)}
			}(),
			roots:           []phase0.Root{rootA},
			expectedBatches: 1,
		},
		{
			name: "AllUnique_NoBatchSplit",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				return []*mockMultiSignerAccount{
					newMockMultiSignerAccount("acct-1", batches),
					newMockMultiSignerAccount("acct-2", batches),
					newMockMultiSignerAccount("acct-3", batches),
				}
			}(),
			roots:           []phase0.Root{rootA, rootB, rootC},
			expectedBatches: 1,
		},
		{
			name: "SameAccountDifferentRoots_TwoBatches",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				return []*mockMultiSignerAccount{a, a}
			}(),
			roots:           []phase0.Root{rootA, rootB},
			expectedBatches: 2,
		},
		{
			name: "SameAccountThreeRoots_ThreeBatches",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				return []*mockMultiSignerAccount{a, a, a}
			}(),
			roots:           []phase0.Root{rootA, rootB, rootC},
			expectedBatches: 3,
		},
		{
			name: "MixedDuplicateAndUnique",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				b := newMockMultiSignerAccount("acct-2", batches)
				// a signs rootA and rootB (2 subnets), b signs rootA (1 subnet).
				return []*mockMultiSignerAccount{a, b, a}
			}(),
			roots:           []phase0.Root{rootA, rootA, rootB},
			expectedBatches: 2,
		},
		{
			name: "DedupAndSplit",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				// a signs rootA twice (dedup removes one), then rootB (split needed).
				return []*mockMultiSignerAccount{a, a, a}
			}(),
			roots:           []phase0.Root{rootA, rootA, rootB},
			expectedBatches: 2,
		},
		{
			name: "SingleBatchFails",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				failOn := 0
				a.failOnBatch = &failOn
				return []*mockMultiSignerAccount{a}
			}(),
			roots: []phase0.Root{rootA},
			err:   "failed to sign generic multi: signing failed",
		},
		{
			name: "SecondBatchFails",
			accounts: func() []*mockMultiSignerAccount {
				batches := &[]batchRecord{}
				a := newMockMultiSignerAccount("acct-1", batches)
				failOn := 1
				a.failOnBatch = &failOn
				// Same account, two different roots → 2 batches needed, second will fail.
				return []*mockMultiSignerAccount{a, a}
			}(),
			roots: []phase0.Root{rootA, rootB},
			err:   "failed to sign generic multi: signing failed",
		},
	}

	svc := &Service{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batches := test.accounts[0].batches
			*batches = nil // Reset between tests.

			accounts := make([]e2wtypes.Account, len(test.accounts))
			for i, a := range test.accounts {
				accounts[i] = a
			}

			sigs, err := svc.signRootsMulti(context.Background(), accounts, test.roots, domain)
			if test.err != "" {
				require.EqualError(t, err, test.err)

				return
			}
			require.NoError(t, err)
			require.Len(t, sigs, len(test.accounts))

			// Verify the number of SignGenericMulti calls (batches).
			require.Len(t, *batches, test.expectedBatches,
				"expected %d SignGenericMulti calls, got %d", test.expectedBatches, len(*batches))

			// Verify each batch has unique account IDs (no duplicate pubkeys).
			for batchIdx, batch := range *batches {
				seen := make(map[uuid.UUID]bool)
				for _, id := range batch.accountIDs {
					require.False(t, seen[id],
						"batch %d contains duplicate account ID %s", batchIdx, id)
					seen[id] = true
				}
			}

			// Verify signature correctness: each (account, root) pair gets the right signature.
			type key struct {
				name string
				root phase0.Root
			}
			sigByKey := make(map[key]phase0.BLSSignature)
			for i, a := range test.accounts {
				k := key{name: a.name, root: test.roots[i]}
				if prev, exists := sigByKey[k]; exists {
					require.Equal(t, prev, sigs[i],
						"duplicate (account, root) pairs must produce identical signatures")
				} else {
					// Non-zero signature.
					require.NotEqual(t, phase0.BLSSignature{}, sigs[i],
						"signature at index %d should not be zero", i)
					sigByKey[k] = sigs[i]
				}
			}
		})
	}
}

func TestSignRootsMulti(t *testing.T) {
	rootA := phase0.Root{0x01}
	rootB := phase0.Root{0x02}
	domain := phase0.Domain{0xAA}

	tests := []struct {
		name             string
		accounts         []*mockSignerAccount
		roots            []phase0.Root
		expectedSignCalls int // total Sign() calls across all accounts
		err              string
	}{
		{
			name:             "AllUnique",
			accounts:         []*mockSignerAccount{newMockAccount("acct-1"), newMockAccount("acct-2"), newMockAccount("acct-3")},
			roots:            []phase0.Root{rootA, rootB, rootA},
			expectedSignCalls: 3,
		},
		{
			name: "AllDuplicates",
			accounts: func() []*mockSignerAccount {
				a := newMockAccount("acct-1")
				return []*mockSignerAccount{a, a, a}
			}(),
			roots:             []phase0.Root{rootA, rootA, rootA},
			expectedSignCalls: 1,
		},
		{
			name: "Mixed",
			accounts: func() []*mockSignerAccount {
				a := newMockAccount("acct-1")
				b := newMockAccount("acct-2")
				return []*mockSignerAccount{a, b, a, b}
			}(),
			roots:             []phase0.Root{rootA, rootB, rootA, rootA},
			expectedSignCalls: 3, // (acct-1,rootA), (acct-2,rootB), (acct-2,rootA)
		},
		{
			name:             "Single",
			accounts:         []*mockSignerAccount{newMockAccount("acct-1")},
			roots:            []phase0.Root{rootA},
			expectedSignCalls: 1,
		},
		{
			name:             "Empty",
			accounts:         []*mockSignerAccount{},
			roots:            []phase0.Root{},
			expectedSignCalls: 0,
			err:              "no accounts; cannot sign",
		},
		{
			name:             "LengthMismatch",
			accounts:         []*mockSignerAccount{newMockAccount("acct-1"), newMockAccount("acct-2")},
			roots:            []phase0.Root{rootA},
			expectedSignCalls: 0,
			err:              "number of accounts and roots do not match",
		},
	}

	svc := &Service{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset sign counts.
			seen := map[string]bool{}
			for _, a := range test.accounts {
				if !seen[a.name] {
					a.signCount = 0
					seen[a.name] = true
				}
			}

			// Convert to interface slices.
			accounts := make([]e2wtypes.Account, len(test.accounts))
			for i, a := range test.accounts {
				accounts[i] = a
			}

			sigs, err := svc.signRootsMulti(context.Background(), accounts, test.roots, domain)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}
			require.NoError(t, err)
			require.Len(t, sigs, len(test.accounts))

			// Verify sign call count matches expected (dedup reduces calls).
			totalSignCalls := 0
			seen = map[string]bool{}
			for _, a := range test.accounts {
				if !seen[a.name] {
					totalSignCalls += a.signCount
					seen[a.name] = true
				}
			}
			require.Equal(t, test.expectedSignCalls, totalSignCalls, "unexpected number of Sign() calls")

			// Verify duplicate (account, root) pairs produce identical signatures.
			type key struct {
				name string
				root phase0.Root
			}
			sigByKey := make(map[key]phase0.BLSSignature)
			for i, a := range test.accounts {
				k := key{name: a.name, root: test.roots[i]}
				if prev, exists := sigByKey[k]; exists {
					require.Equal(t, prev, sigs[i], "duplicate (account, root) pairs must produce identical signatures")
				} else {
					sigByKey[k] = sigs[i]
				}
			}
		})
	}
}
