// Copyright © 2022 Attestant Limited.
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

package mevboost

import (
	"context"
	"time"

	"github.com/attestantio/go-builder-client/api"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SubmitValidatorRegistrations submits validator registrations.
func (s *Service) SubmitValidatorRegistrations(ctx context.Context,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
	feeRecipients map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
) error {
	signedRegistrations := make([]*api.VersionedSignedValidatorRegistration, 0, len(accounts))

	var pubkey phase0.BLSPubKey
	var feeRecipient bellatrix.ExecutionAddress
	for index, account := range accounts {
		var accountPubkey e2types.PublicKey
		if provider, isProvider := account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
			accountPubkey = provider.CompositePublicKey()
		} else {
			accountPubkey = account.(e2wtypes.AccountPublicKeyProvider).PublicKey()
		}
		copy(pubkey[:], accountPubkey.Marshal())

		var exists bool
		feeRecipient, exists = feeRecipients[index]
		if !exists {
			// Log an error but continue.
			log.Error().Uint64("index", uint64(index)).Msg("Validator does not have fee recipient; cannot register")
			continue
		}

		registration := &apiv1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			GasLimit:     s.gasLimit,
			Timestamp:    time.Now().Round(time.Second),
			Pubkey:       pubkey,
		}

		// TODO see if we have already submitted this registration, and if so do not re-send?
		// TODO consider if we do want to resend, and how frequently.

		sig, err := s.validatorRegistrationSigner.SignValidatorRegistration(ctx, account, &api.VersionedValidatorRegistration{
			Version: spec.BuilderVersionV1,
			V1:      registration,
		})
		if err != nil {
			// Log an error but continue.
			log.Error().Err(err).Uint64("index", uint64(index)).Msg("Failed to sign validator registration")
			continue
		}

		signedRegistration := &apiv1.SignedValidatorRegistration{
			Message:   registration,
			Signature: sig,
		}

		signedRegistrations = append(signedRegistrations, &api.VersionedSignedValidatorRegistration{
			Version: spec.BuilderVersionV1,
			V1:      signedRegistration,
		})
	}

	if err := s.validatorRegistrationsSubmitter.SubmitValidatorRegistrations(ctx, signedRegistrations); err != nil {
		return errors.Wrap(err, "failed to submit validator registrations")
	}

	return nil
}
