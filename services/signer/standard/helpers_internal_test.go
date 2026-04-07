// Copyright © 2020-2026 Attestant Limited.
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

func newMockAccount(name string) *mockSignerAccount {
	return &mockSignerAccount{
		id:     uuid.New(),
		name:   name,
		pubKey: &mockPublicKey{data: []byte(name)},
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
