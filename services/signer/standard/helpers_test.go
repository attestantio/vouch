// Copyright © 2025 Attestant Limited.
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
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// mockAccount implements the e2wtypes.Account interface for testing
type mockAccount struct {
	id        uuid.UUID
	name      string
	publicKey e2types.PublicKey
}

func (m *mockAccount) ID() uuid.UUID {
	return m.id
}

func (m *mockAccount) Name() string {
	return m.name
}

func (m *mockAccount) PublicKey() e2types.PublicKey {
	return m.publicKey
}

// mockMultiSigner implements both Account and AccountProtectingMultiSigner
type mockMultiSigner struct {
	*mockAccount
	signGenericMultiCalls []signGenericMultiCall
	signGenericMultiFunc  func(ctx context.Context, accounts []e2wtypes.Account, data [][]byte, domain []byte) ([]e2types.Signature, error)
}

type signGenericMultiCall struct {
	accounts []e2wtypes.Account
	data     [][]byte
	domain   []byte
}

// skipcq: RVV-B0012, RVV-B0013
// This is just a stub to satisfy the interface.
func (*mockMultiSigner) SignBeaconAttestations(_ context.Context,
	_ uint64,
	_ []e2wtypes.Account,
	_ []uint64,
	_ []byte,
	_ uint64,
	_ []byte,
	_ uint64,
	_ []byte,
	_ []byte) ([]e2types.Signature, error) {
	return nil, fmt.Errorf("SignBeaconAttestations not implemented in mock")
}

func (m *mockMultiSigner) SignGenericMulti(ctx context.Context, accounts []e2wtypes.Account, data [][]byte, domain []byte) ([]e2types.Signature, error) {
	// Record the call for verification
	m.signGenericMultiCalls = append(m.signGenericMultiCalls, signGenericMultiCall{
		accounts: accounts,
		data:     data,
		domain:   domain,
	})

	if m.signGenericMultiFunc != nil {
		return m.signGenericMultiFunc(ctx, accounts, data, domain)
	}

	// Return deterministic mock signatures
	signatures := make([]e2types.Signature, len(accounts))
	for i := range signatures {
		privKey, err := e2types.GenerateBLSPrivateKey()
		if err != nil {
			return nil, err
		}

		message := fmt.Sprintf("test-signature-%s-%x", accounts[i].Name(), data[i][:8])
		sig := privKey.Sign([]byte(message))
		signatures[i] = sig
	}
	return signatures, nil
}

// mockSequentialSigner implements only Account and AccountSigner (not AccountProtectingMultiSigner)
// This forces the sequential signing path in signRootsMulti
type mockSequentialSigner struct {
	*mockAccount
	signCalls []signCall
	signFunc  func(ctx context.Context, data []byte) (e2types.Signature, error)
}

type signCall struct {
	data []byte
}

func (m *mockSequentialSigner) Sign(ctx context.Context, data []byte) (e2types.Signature, error) {
	// Record the call for verification
	m.signCalls = append(m.signCalls, signCall{
		data: data,
	})

	if m.signFunc != nil {
		return m.signFunc(ctx, data)
	}

	// Return deterministic mock signature
	privKey, err := e2types.GenerateBLSPrivateKey()
	if err != nil {
		return nil, err
	}

	message := fmt.Sprintf("sequential-signature-%s-%x", m.Name(), data[:8])
	sig := privKey.Sign([]byte(message))
	return sig, nil
}

func TestSignRootsMultiWithDuplicates(t *testing.T) {
	// Initialize BLS
	err := e2types.InitBLS()
	require.NoError(t, err)

	// Generate real public keys for the accounts
	privKey1, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)

	// Create mock accounts
	account1 := &mockAccount{
		id:        uuid.New(),
		name:      "account1",
		publicKey: privKey1.PublicKey(),
	}

	// Create test roots
	root1 := phase0.Root{1, 2, 3, 4}
	root2 := phase0.Root{5, 6, 7, 8}
	domain := phase0.Domain{9, 10, 11, 12}

	// Test both multi-signer and sequential signing paths
	testCases := []struct {
		name   string
		signer e2wtypes.Account
	}{
		{
			name: "MultiSigner",
			signer: &mockMultiSigner{
				mockAccount: account1,
			},
		},
		{
			name: "SequentialSigner",
			signer: &mockSequentialSigner{
				mockAccount: account1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset any state if needed
			if ms, ok := tc.signer.(*mockMultiSigner); ok {
				ms.signGenericMultiCalls = nil
			}
			if ss, ok := tc.signer.(*mockSequentialSigner); ok {
				ss.signCalls = nil
			}

			// Test case with duplicates: same account signing same root multiple times
			accounts := []e2wtypes.Account{tc.signer, tc.signer, tc.signer}
			roots := []phase0.Root{root1, root1, root2} // Two identical roots, one different

			// Create service instance
			service := &Service{}

			// Call the signRootsMulti method directly
			signatures, err := service.signRootsMulti(context.Background(), accounts, roots, domain)
			require.NoError(t, err)
			require.Equal(t, 3, len(signatures), "Should return 3 signatures")

			// Verify deduplication worked based on signer type
			if ms, ok := tc.signer.(*mockMultiSigner); ok {
				// Multi-signer path verification
				require.Equal(t, 1, len(ms.signGenericMultiCalls), "SignGenericMulti should be called exactly once")
				call := ms.signGenericMultiCalls[0]
				assert.Equal(t, 2, len(call.accounts), "Should have 2 unique accounts (deduplicated)")
				assert.Equal(t, 2, len(call.data), "Should have 2 unique data items (deduplicated)")
				assert.Equal(t, domain[:], call.domain, "Domain should be passed unchanged")
			} else if ss, ok := tc.signer.(*mockSequentialSigner); ok {
				// Sequential signer path verification
				require.Equal(t, 2, len(ss.signCalls), "Sequential signer should be called exactly twice (deduplicated)")
			}

			// Verify that all signatures are valid (not zero)
			for i, sig := range signatures {
				assert.NotEqual(t, phase0.BLSSignature{}, sig, "Signature %d should not be zero", i)
			}

			// The key test: signatures[0] and signatures[1] should be identical (same account, same root)
			// This proves that the deduplication worked and the same signature was reused
			assert.Equal(t, signatures[0], signatures[1], "Signatures for identical (account, root) pairs should be the same - this proves deduplication worked")

			// signature[2] should be different (different root)
			assert.NotEqual(t, signatures[0], signatures[2], "Signatures for different roots should be different")
		})
	}
}

func TestSignRootsMultiWithMultipleDuplicates(t *testing.T) {
	// Initialize BLS
	err := e2types.InitBLS()
	require.NoError(t, err)

	// Generate real public key for the account
	privKey1, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)

	// Create mock account
	account1 := &mockAccount{
		id:        uuid.New(),
		name:      "account1",
		publicKey: privKey1.PublicKey(),
	}

	// Create test roots
	root1 := phase0.Root{1, 2, 3, 4}
	root2 := phase0.Root{5, 6, 7, 8}
	root3 := phase0.Root{9, 10, 11, 12}
	domain := phase0.Domain{13, 14, 15, 16}

	// Test both multi-signer and sequential signing paths
	testCases := []struct {
		name   string
		signer e2wtypes.Account
	}{
		{
			name: "MultiSigner",
			signer: &mockMultiSigner{
				mockAccount: account1,
			},
		},
		{
			name: "SequentialSigner",
			signer: &mockSequentialSigner{
				mockAccount: account1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset any state if needed
			if ms, ok := tc.signer.(*mockMultiSigner); ok {
				ms.signGenericMultiCalls = nil
			}
			if ss, ok := tc.signer.(*mockSequentialSigner); ok {
				ss.signCalls = nil
			}

			// Complex pattern with the same account signing different combinations
			// Pattern: root1, root1, root2, root1, root2, root3, root1
			// Expected unique pairs: (acc1, root1), (acc1, root2), (acc1, root3) = 3 unique pairs
			accounts := []e2wtypes.Account{tc.signer, tc.signer, tc.signer, tc.signer, tc.signer, tc.signer, tc.signer}
			roots := []phase0.Root{root1, root1, root2, root1, root2, root3, root1}

			// Create service instance
			service := &Service{}

			// Call the signRootsMulti method directly
			signatures, err := service.signRootsMulti(context.Background(), accounts, roots, domain)
			require.NoError(t, err)
			require.Equal(t, 7, len(signatures), "Should return 7 signatures")

			// Verify deduplication worked based on signer type
			if ms, ok := tc.signer.(*mockMultiSigner); ok {
				// Multi-signer path verification
				require.Equal(t, 1, len(ms.signGenericMultiCalls), "MultiSigner should be called exactly once")
				call := ms.signGenericMultiCalls[0]
				assert.Equal(t, 3, len(call.accounts), "MultiSigner should have 3 unique pairs")
				assert.Equal(t, 3, len(call.data), "MultiSigner should have 3 unique data items")
			} else if ss, ok := tc.signer.(*mockSequentialSigner); ok {
				// Sequential signer path verification
				require.Equal(t, 3, len(ss.signCalls), "Sequential signer should be called exactly three times (deduplicated)")
			}

			// Verify duplicate signatures are identical
			assert.Equal(t, signatures[0], signatures[1], "signatures[0] and signatures[1] should be identical (same root)")
			assert.Equal(t, signatures[0], signatures[3], "signatures[0] and signatures[3] should be identical (same root)")
			assert.Equal(t, signatures[0], signatures[6], "signatures[0] and signatures[6] should be identical (same root)")
			assert.Equal(t, signatures[2], signatures[4], "signatures[2] and signatures[4] should be identical (same root)")

			// Verify different signatures are not equal
			assert.NotEqual(t, signatures[0], signatures[2], "Different roots should have different signatures")
			assert.NotEqual(t, signatures[0], signatures[5], "Different roots should have different signatures")
			assert.NotEqual(t, signatures[2], signatures[5], "Different roots should have different signatures")
		})
	}
}

func TestDeduplicateAccountRootPairs(t *testing.T) {
	// Test the dedicated deduplication function
	err := e2types.InitBLS()
	require.NoError(t, err)

	// Create mock accounts with real public keys
	privKey1, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)
	privKey2, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)

	account1 := &mockAccount{
		id:        uuid.New(),
		name:      "account1",
		publicKey: privKey1.PublicKey(),
	}
	account2 := &mockAccount{
		id:        uuid.New(),
		name:      "account2",
		publicKey: privKey2.PublicKey(),
	}

	tests := []struct {
		name                   string
		accounts               []e2wtypes.Account
		data                   [][]byte
		expectedUniqueAccounts int
		expectedUniqueData     int
		expectedMapping        []int
	}{
		{
			name:                   "NoDuplicates",
			accounts:               []e2wtypes.Account{account1, account2},
			data:                   [][]byte{{1, 2, 3}, {4, 5, 6}},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "SameAccountDifferentData",
			accounts:               []e2wtypes.Account{account1, account1},
			data:                   [][]byte{{1, 2, 3}, {4, 5, 6}},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "DifferentAccountsSameData",
			accounts:               []e2wtypes.Account{account1, account2},
			data:                   [][]byte{{1, 2, 3}, {1, 2, 3}},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "ExactDuplicates",
			accounts:               []e2wtypes.Account{account1, account1},
			data:                   [][]byte{{1, 2, 3}, {1, 2, 3}},
			expectedUniqueAccounts: 1,
			expectedUniqueData:     1,
			expectedMapping:        []int{0, 0},
		},
		{
			name:                   "MultipleDuplicates",
			accounts:               []e2wtypes.Account{account1, account1, account1, account1},
			data:                   [][]byte{{1, 2, 3}, {1, 2, 3}, {1, 2, 3}, {1, 2, 3}},
			expectedUniqueAccounts: 1,
			expectedUniqueData:     1,
			expectedMapping:        []int{0, 0, 0, 0},
		},
		{
			name:                   "MixedDuplicatesAndUnique",
			accounts:               []e2wtypes.Account{account1, account1, account2},
			data:                   [][]byte{{1, 2, 3}, {1, 2, 3}, {1, 2, 3}},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 0, 1},
		},
		{
			name:                   "ComplexPattern",
			accounts:               []e2wtypes.Account{account1, account2, account1, account2, account1},
			data:                   [][]byte{{1, 2, 3}, {1, 2, 3}, {4, 5, 6}, {1, 2, 3}, {1, 2, 3}},
			expectedUniqueAccounts: 3,
			expectedUniqueData:     3,
			expectedMapping:        []int{0, 1, 2, 1, 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{}
			result := service.deduplicateAccountRootPairs(test.accounts, test.data)

			// Verify results
			assert.Equal(t, test.expectedUniqueAccounts, len(result.uniqueAccounts), "Unique accounts count mismatch")
			assert.Equal(t, test.expectedUniqueData, len(result.uniqueData), "Unique data count mismatch")
			assert.Equal(t, test.expectedMapping, result.originalToUniqueIndex, "Index mapping mismatch")

			// Verify that mapping back works correctly
			for i := range test.accounts {
				uniqueIndex := result.originalToUniqueIndex[i]
				assert.Equal(t, test.accounts[i], result.uniqueAccounts[uniqueIndex], "Account mapping incorrect at index %d", i)
				assert.Equal(t, test.data[i], result.uniqueData[uniqueIndex], "Data mapping incorrect at index %d", i)
			}

			// Verify that unique accounts and data are consistent
			for i, account := range result.uniqueAccounts {
				expectedData := test.data[0] // Find first occurrence data for this account
				for j, origAccount := range test.accounts {
					if origAccount == account && assert.ObjectsAreEqualValues(test.data[j], result.uniqueData[i]) {
						expectedData = test.data[j]
						break
					}
				}
				assert.Equal(t, expectedData, result.uniqueData[i], "Unique data should match expected data for account at index %d", i)
			}
		})
	}
}
