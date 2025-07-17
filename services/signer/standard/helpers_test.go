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
func (_ *mockMultiSigner) SignBeaconAttestations(_ context.Context,
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

	// Create a multi-signer that wraps the first account
	multiSigner := &mockMultiSigner{
		mockAccount: account1,
	}

	// Create test roots
	root1 := phase0.Root{1, 2, 3, 4}
	root2 := phase0.Root{5, 6, 7, 8}

	// Test case with duplicates: same account signing same root multiple times
	accounts := []e2wtypes.Account{multiSigner, multiSigner, multiSigner}
	roots := []phase0.Root{root1, root1, root2} // Two identical roots, one different
	domain := phase0.Domain{9, 10, 11, 12}

	// Create service instance
	service := &Service{}

	// Call the signRootsMulti method directly
	signatures, err := service.signRootsMulti(context.Background(), accounts, roots, domain)
	require.NoError(t, err)
	require.Equal(t, 3, len(signatures), "Should return 3 signatures")

	// Verify that the multi-signer was called with deduplicated data
	require.Equal(t, 1, len(multiSigner.signGenericMultiCalls), "SignGenericMulti should be called exactly once")

	call := multiSigner.signGenericMultiCalls[0]

	// Should have only 2 unique (account, root) pairs instead of 3
	assert.Equal(t, 2, len(call.accounts), "Should have 2 unique accounts (deduplicated)")
	assert.Equal(t, 2, len(call.data), "Should have 2 unique data items (deduplicated)")

	// Verify the domain was passed correctly
	assert.Equal(t, domain[:], call.domain, "Domain should be passed unchanged")

	// Verify the deduplicated data contains the expected unique pairs
	expectedData1 := root1[:] // First unique root
	expectedData2 := root2[:] // Second unique root

	// The deduplication should result in these two unique data items
	actualData1 := call.data[0]
	actualData2 := call.data[1]

	// Verify we have the expected roots (order might vary due to map iteration)
	assert.True(t,
		(assert.ObjectsAreEqualValues(expectedData1, actualData1) && assert.ObjectsAreEqualValues(expectedData2, actualData2)) ||
			(assert.ObjectsAreEqualValues(expectedData1, actualData2) && assert.ObjectsAreEqualValues(expectedData2, actualData1)),
		"Deduplicated data should contain exactly the two unique roots")

	// Verify that all signatures are valid (not zero)
	for i, sig := range signatures {
		assert.NotEqual(t, phase0.BLSSignature{}, sig, "Signature %d should not be zero", i)
	}

	// The key test: signatures[0] and signatures[1] should be identical (same account, same root)
	// This proves that the deduplication worked and the same signature was reused
	assert.Equal(t, signatures[0], signatures[1], "Signatures for identical (account, root) pairs should be the same - this proves deduplication worked")

	// signature[2] should be different (different root)
	assert.NotEqual(t, signatures[0], signatures[2], "Signatures for different roots should be different")
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

	// Create a multi-signer that wraps the account
	multiSigner := &mockMultiSigner{
		mockAccount: account1,
	}

	// Create test roots
	root1 := phase0.Root{1, 2, 3, 4}
	root2 := phase0.Root{5, 6, 7, 8}
	root3 := phase0.Root{9, 10, 11, 12}

	// Complex pattern with the same account signing different combinations
	// Pattern: root1, root1, root2, root1, root2, root3, root1
	// Expected unique pairs: (acc1, root1), (acc1, root2), (acc1, root3) = 3 unique pairs
	accounts := []e2wtypes.Account{multiSigner, multiSigner, multiSigner, multiSigner, multiSigner, multiSigner, multiSigner}
	roots := []phase0.Root{root1, root1, root2, root1, root2, root3, root1}
	domain := phase0.Domain{13, 14, 15, 16}

	// Create service instance
	service := &Service{}

	// Call the signRootsMulti method directly
	signatures, err := service.signRootsMulti(context.Background(), accounts, roots, domain)
	require.NoError(t, err)
	require.Equal(t, 7, len(signatures), "Should return 7 signatures")

	// Verify multiSigner was called with its unique pairs
	require.Equal(t, 1, len(multiSigner.signGenericMultiCalls), "MultiSigner should be called exactly once")
	call := multiSigner.signGenericMultiCalls[0]

	// Should have 3 unique pairs: (acc1, root1), (acc1, root2), (acc1, root3)
	assert.Equal(t, 3, len(call.accounts), "MultiSigner should have 3 unique pairs")
	assert.Equal(t, 3, len(call.data), "MultiSigner should have 3 unique data items")

	// Verify duplicate signatures are identical
	assert.Equal(t, signatures[0], signatures[1], "signatures[0] and signatures[1] should be identical (same root)")
	assert.Equal(t, signatures[0], signatures[3], "signatures[0] and signatures[3] should be identical (same root)")
	assert.Equal(t, signatures[0], signatures[6], "signatures[0] and signatures[6] should be identical (same root)")
	assert.Equal(t, signatures[2], signatures[4], "signatures[2] and signatures[4] should be identical (same root)")

	// Verify different signatures are not equal
	assert.NotEqual(t, signatures[0], signatures[2], "Different roots should have different signatures")
	assert.NotEqual(t, signatures[0], signatures[5], "Different roots should have different signatures")
	assert.NotEqual(t, signatures[2], signatures[5], "Different roots should have different signatures")
}
