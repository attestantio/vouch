// Copyright © 2023 Attestant Limited.
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
	"time"

	blockrelayauctioneer "github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	apiv1fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func duty(slot phase0.Slot, validatorIndex phase0.ValidatorIndex, randaoReveal phase0.BLSSignature, account e2wtypes.Account) *beaconblockproposer.Duty {
	duty := beaconblockproposer.NewDuty(slot, validatorIndex)
	duty.SetRandaoReveal(randaoReveal)
	duty.SetAccount(account)
	return duty
}

func TestValidateDuty(t *testing.T) {
	ctx := context.Background()

	// Create an account.
	require.NoError(t, e2types.InitBLS())
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet(ctx, "test wallet", []byte("pass"), store, encryptor, make([]byte, 64))
	require.NoError(t, err)
	require.Nil(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
	account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "test account", []byte("pass"))
	require.NoError(t, err)
	require.NoError(t, account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("pass")))

	sig, err := account.(e2wtypes.AccountSigner).Sign(ctx, []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	require.NoError(t, err)
	randaoReveal := phase0.BLSSignature(sig.Marshal())

	tests := []struct {
		name string
		duty *beaconblockproposer.Duty
		slot phase0.Slot
		err  string
	}{
		{
			name: "Nil",
			err:  "no duty supplied",
		},
		{
			name: "NoRandaoReveal",
			duty: duty(1, 2, phase0.BLSSignature{}, account),
			err:  "duty missing RANDAO reveal",
		},
		{
			name: "NoAccount",
			duty: duty(1, 2, randaoReveal, nil),
			err:  "duty missing account",
		},
		{
			name: "Good",
			duty: duty(1, 2, randaoReveal, account),
			slot: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot, err := validateDuty(test.duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.slot, slot)
			}
		})
	}
}

func TestSubmitProposal(t *testing.T) {
	ctx := context.Background()

	// Create a service with minimal setup for testing.
	s := &Service{
		log: zerolog.New(zerolog.NewTestWriter(t)),
	}

	tests := []struct {
		name           string
		setupProviders func() []builderclient.SubmitBlindedProposalProvider
		timeout        time.Duration
		expectedError  string
		validateCalls  func(*testing.T, []builderclient.SubmitBlindedProposalProvider)
	}{
		{
			name: "Success_SingleProvider",
			setupProviders: func() []builderclient.SubmitBlindedProposalProvider {
				return []builderclient.SubmitBlindedProposalProvider{
					mock.NewSubmitBlindedProposalProvider(),
				}
			},
			validateCalls: func(t *testing.T, providers []builderclient.SubmitBlindedProposalProvider) {
				t.Helper()
				provider := providers[0].(*mock.CustomSubmitBlindedProposalProvider)
				require.Equal(t, 1, provider.GetCallCount())
			},
		},
		{
			name: "Success_MultipleProviders_FirstWins",
			setupProviders: func() []builderclient.SubmitBlindedProposalProvider {
				return []builderclient.SubmitBlindedProposalProvider{
					mock.NewSlowSubmitBlindedProposalProvider(10 * time.Millisecond),
					mock.NewSlowSubmitBlindedProposalProvider(100 * time.Millisecond),
					mock.NewSlowSubmitBlindedProposalProvider(500 * time.Millisecond),
				}
			},
			validateCalls: func(t *testing.T, providers []builderclient.SubmitBlindedProposalProvider) {
				t.Helper()
				// First provider should complete
				fast := providers[0].(*mock.CustomSubmitBlindedProposalProvider)
				require.Equal(t, 1, fast.GetCallCount())
			},
		},
		{
			name: "Retry_500Error_ThreeTimes",
			setupProviders: func() []builderclient.SubmitBlindedProposalProvider {
				return []builderclient.SubmitBlindedProposalProvider{
					mock.NewErroringSubmitBlindedProposalProvider("500"),
				}
			},
			timeout:       2 * time.Second, // Need timeout since all retries fail
			expectedError: "failed to submit blinded block to relay",
			validateCalls: func(t *testing.T, providers []builderclient.SubmitBlindedProposalProvider) {
				t.Helper()
				provider := providers[0].(*mock.CustomSubmitBlindedProposalProvider)
				// Verifies retry logic executed 3 times
				require.Equal(t, 3, provider.GetCallCount())
			},
		},
		{
			name: "Retry_404_NoRetry",
			setupProviders: func() []builderclient.SubmitBlindedProposalProvider {
				return []builderclient.SubmitBlindedProposalProvider{
					mock.NewErroringSubmitBlindedProposalProvider("404"),
				}
			},
			timeout:       1 * time.Second, // Need timeout since 404 doesn't send to channel
			expectedError: "failed to submit blinded block to relay",
			validateCalls: func(t *testing.T, providers []builderclient.SubmitBlindedProposalProvider) {
				t.Helper()
				provider := providers[0].(*mock.CustomSubmitBlindedProposalProvider)
				// Should only be called once (no retry on 404)
				require.Equal(t, 1, provider.GetCallCount())
			},
		},
		{
			name: "Context_Timeout",
			setupProviders: func() []builderclient.SubmitBlindedProposalProvider {
				return []builderclient.SubmitBlindedProposalProvider{
					mock.NewSlowSubmitBlindedProposalProvider(5 * time.Second),
				}
			},
			timeout:       100 * time.Millisecond,
			expectedError: "failed to submit blinded block to relay",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providers := test.setupProviders()

			// Create proposal for all protocol versions.
			proposal := &consensusapi.VersionedSignedProposal{
				Version: spec.DataVersionDeneb,
				DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
					Message: &apiv1deneb.BlindedBeaconBlock{
						Slot: 123,
					},
				},
			}

			testCtx := ctx
			if test.timeout > 0 {
				var cancel context.CancelFunc
				testCtx, cancel = context.WithTimeout(ctx, test.timeout)
				defer cancel()
			}

			err := s.submitProposal(testCtx, proposal, providers)

			if test.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedError)
			} else {
				require.NoError(t, err)
			}

			if test.validateCalls != nil {
				test.validateCalls(t, providers)
			}
		})
	}
}

func TestSubmitBlindedProposal(t *testing.T) {
	tests := []struct {
		name          string
		version       spec.DataVersion
		setupMocks    func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal)
		timeout       time.Duration
		expectedError string
		logCheck      func(*testing.T, *logger.LogCapture)
	}{
		{
			name:    "Success_Deneb",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}
				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
				}
				proposal := &consensusapi.VersionedSignedProposal{
					Version:  spec.DataVersionDeneb,
					Blinded:  true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
		},
		{
			name:    "Success_Electra",
			version: spec.DataVersionElectra,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}
				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
				}
				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionElectra,
					Blinded: true,
					ElectraBlinded: &apiv1electra.SignedBlindedBeaconBlock{
						Message: &apiv1electra.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
		},
		{
			name:    "Success_Fulu",
			version: spec.DataVersionFulu,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}
				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewSubmitBlindedProposalProvider(),
					},
				}
				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionFulu,
					Blinded: true,
					FuluBlinded: &apiv1electra.SignedBlindedBeaconBlock{
						Message: &apiv1electra.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
		},
		{
			name:    "Fallback_404_AllProviders",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}
				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewErroringSubmitBlindedProposalProvider("404"),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewErroringSubmitBlindedProposalProvider("404"),
					},
				}
				proposal := &consensusapi.VersionedSignedProposal{
					Version:  spec.DataVersionDeneb,
					Blinded:  true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			timeout:       1 * time.Second,
			expectedError: "failed to submit blinded block to relay",
		},
		{
			name:    "NoProviders",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}
				auctionResults := &blockrelayauctioneer.Results{
					Providers:    []builderclient.BuilderBidProvider{},
					AllProviders: []builderclient.BuilderBidProvider{},
				}
				proposal := &consensusapi.VersionedSignedProposal{
					Version:  spec.DataVersionDeneb,
					Blinded:  true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			expectedError: "no relays to submit the blinded block to",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, auctionResults, proposal := test.setupMocks()

			ctx := context.Background()
			if test.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.timeout)
				defer cancel()
			}

			err := s.submitBlindedProposal(ctx, auctionResults, proposal)

			if test.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedError)
			} else {
				require.NoError(t, err)
			}

			if test.logCheck != nil {
				test.logCheck(t, capture)
			}
		})
	}
}

func TestSubmitAndUnblindProposal(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		version       spec.DataVersion
		setupMocks    func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal)
		timeout       time.Duration
		expectedError string
		validateState func(*testing.T, *consensusapi.VersionedSignedProposal)
	}{
		{
			name:    "Success_Bellatrix",
			version: spec.DataVersionBellatrix,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				// Unblinded response.
				unblindedProposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionBellatrix,
					Bellatrix: &bellatrix.SignedBeaconBlock{
						Message: &bellatrix.BeaconBlock{
							Slot: 123,
						},
					},
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
				}

				// Blinded proposal.
				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionBellatrix,
					Blinded: true,
					BellatrixBlinded: &apiv1bellatrix.SignedBlindedBeaconBlock{
						Message: &apiv1bellatrix.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			validateState: func(t *testing.T, proposal *consensusapi.VersionedSignedProposal) {
				t.Helper()
				require.False(t, proposal.Blinded, "Proposal should be unblinded")
				require.NotNil(t, proposal.Bellatrix)
			},
		},
		{
			name:    "Success_Capella",
			version: spec.DataVersionCapella,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				unblindedProposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionCapella,
					Capella: &capella.SignedBeaconBlock{
						Message: &capella.BeaconBlock{
							Slot: 123,
						},
					},
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionCapella,
					Blinded: true,
					CapellaBlinded: &apiv1capella.SignedBlindedBeaconBlock{
						Message: &apiv1capella.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			validateState: func(t *testing.T, proposal *consensusapi.VersionedSignedProposal) {
				t.Helper()
				require.False(t, proposal.Blinded, "Proposal should be unblinded")
				require.NotNil(t, proposal.Capella)
			},
		},
		{
			name:    "Success_Deneb",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				unblindedProposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionDeneb,
					Deneb: &apiv1deneb.SignedBlockContents{
						SignedBlock: &deneb.SignedBeaconBlock{
							Message: &deneb.BeaconBlock{
								Slot: 123,
							},
						},
					},
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionDeneb,
					Blinded: true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			validateState: func(t *testing.T, proposal *consensusapi.VersionedSignedProposal) {
				t.Helper()
				require.False(t, proposal.Blinded, "Proposal should be unblinded")
				require.NotNil(t, proposal.Deneb)
			},
		},
		{
			name:    "Success_Electra",
			version: spec.DataVersionElectra,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				unblindedProposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionElectra,
					Electra: &apiv1electra.SignedBlockContents{
						SignedBlock: &electra.SignedBeaconBlock{
							Message: &electra.BeaconBlock{
								Slot: 123,
							},
						},
					},
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionElectra,
					Blinded: true,
					ElectraBlinded: &apiv1electra.SignedBlindedBeaconBlock{
						Message: &apiv1electra.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			validateState: func(t *testing.T, proposal *consensusapi.VersionedSignedProposal) {
				t.Helper()
				require.False(t, proposal.Blinded, "Proposal should be unblinded")
				require.NotNil(t, proposal.Electra)
			},
		},
		{
			name:    "Success_Fulu",
			version: spec.DataVersionFulu,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				unblindedProposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionFulu,
					Fulu: &apiv1fulu.SignedBlockContents{
						SignedBlock: &electra.SignedBeaconBlock{
							Message: &electra.BeaconBlock{
								Slot: 123,
							},
						},
					},
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewUnblindedProposalProvider(unblindedProposal),
					},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionFulu,
					Blinded: true,
					FuluBlinded: &apiv1electra.SignedBlindedBeaconBlock{
						Message: &apiv1electra.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			validateState: func(t *testing.T, proposal *consensusapi.VersionedSignedProposal) {
				t.Helper()
				require.False(t, proposal.Blinded, "Proposal should be unblinded")
				require.NotNil(t, proposal.Fulu)
			},
		},
		{
			name:    "Retry_400_NoRetry",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers: []builderclient.BuilderBidProvider{
						mock.NewErroringUnblindedProposalProvider("400"),
					},
					AllProviders: []builderclient.BuilderBidProvider{
						mock.NewErroringUnblindedProposalProvider("400"),
					},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionDeneb,
					Blinded: true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			timeout:       1 * time.Second, // Need timeout since 400 doesn't send to channel
			expectedError: "failed to obtain unblinded block",
		},
		{
			name:    "NoProviders",
			version: spec.DataVersionDeneb,
			setupMocks: func() (*Service, *blockrelayauctioneer.Results, *consensusapi.VersionedSignedProposal) {
				s := &Service{
					log: zerolog.New(zerolog.NewTestWriter(t)),
				}

				auctionResults := &blockrelayauctioneer.Results{
					Providers:    []builderclient.BuilderBidProvider{},
					AllProviders: []builderclient.BuilderBidProvider{},
				}

				proposal := &consensusapi.VersionedSignedProposal{
					Version: spec.DataVersionDeneb,
					Blinded: true,
					DenebBlinded: &apiv1deneb.SignedBlindedBeaconBlock{
						Message: &apiv1deneb.BlindedBeaconBlock{
							Slot: 123,
						},
					},
				}
				return s, auctionResults, proposal
			},
			expectedError: "no relays to unblind the block",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, auctionResults, proposal := test.setupMocks()

			testCtx := ctx
			if test.timeout > 0 {
				var cancel context.CancelFunc
				testCtx, cancel = context.WithTimeout(ctx, test.timeout)
				defer cancel()
			}

			err := s.submitAndUnblindProposal(testCtx, auctionResults, proposal)

			if test.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedError)
			} else {
				require.NoError(t, err)
				if test.validateState != nil {
					test.validateState(t, proposal)
				}
			}
		})
	}
}

