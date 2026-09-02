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

package standard_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/services/proposerpreferences/standard"
	"github.com/attestantio/vouch/testutil"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestPublishSignsAndSubmitsEachDistinctPreferenceOnce(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{signature: phase0.BLSSignature{0x01}}
	submitter := &recordingSubmitter{outcomes: map[string]error{"one": nil, "two": nil}}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(signer),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)

	duty := proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)

	require.NoError(t, service.Publish(ctx, duty))
	require.NoError(t, service.Publish(ctx, duty))

	require.Len(t, signer.preferences, 1)
	require.Equal(t, &gloas.ProposerPreferences{
		DependentRoot:  phase0.Root{0x01},
		ProposalSlot:   64,
		ValidatorIndex: 3,
		FeeRecipient:   bellatrix.ExecutionAddress{0x02},
		TargetGasLimit: 30_000_000,
	}, signer.preferences[0])
	require.Len(t, submitter.preferences, 1)
	require.Equal(t, signer.signature, submitter.preferences[0][0].Signature)
	require.Same(t, signer.preferences[0], submitter.preferences[0][0].Message)
}

func TestPublishRejectsMissingProviderOutcomes(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{}),
		standard.WithSubmitter(&recordingSubmitter{}),
	)
	require.NoError(t, err)

	err = service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	))

	require.EqualError(t, err, "no proposer preferences submission outcomes")
}

type recordingSigner struct {
	preferences []*gloas.ProposerPreferences
	signature   phase0.BLSSignature
}

func (s *recordingSigner) SignProposerPreferences(_ context.Context,
	_ e2wtypes.Account,
	preferences *gloas.ProposerPreferences,
) (
	phase0.BLSSignature,
	error,
) {
	s.preferences = append(s.preferences, preferences)
	return s.signature, nil
}

type recordingSubmitter struct {
	preferences [][]*gloas.SignedProposerPreferences
	outcomes    map[string]error
}

func (s *recordingSubmitter) SubmitProposerPreferences(_ context.Context,
	preferences []*gloas.SignedProposerPreferences,
) map[string]error {
	s.preferences = append(s.preferences, preferences)
	return s.outcomes
}
