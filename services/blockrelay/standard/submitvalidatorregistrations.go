// Copyright © 2022 - 2024 Attestant Limited.
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	builderclient "github.com/attestantio/go-builder-client"
	builderapi "github.com/attestantio/go-builder-client/api"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderspec "github.com/attestantio/go-builder-client/spec"
	eth2client "github.com/attestantio/go-eth2-client"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	consensusapiv1 "github.com/attestantio/go-eth2-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func (s *Service) submitValidatorRegistrationsRuntime(_ context.Context) (
	time.Time,
	error,
) {
	// Schedule for an arbitrary time in the middle 80% of the next epoch, to avoid overloading the relays
	// with lots of simultaneous registrations.
	currentEpoch := s.chainTime.CurrentEpoch()
	epochDuration := s.chainTime.StartOfEpoch(currentEpoch + 1).Sub(s.chainTime.StartOfEpoch(currentEpoch))
	//nolint:gosec // Secure random number generation not required.
	offset := ((10 + rand.Int63n(80)) * epochDuration.Milliseconds()) / 100
	return s.chainTime.StartOfEpoch(currentEpoch + 1).Add(time.Duration(offset) * time.Millisecond), nil
}

// SubmitValidatorRegistrations submits validator registrations for the given accounts.
func (s *Service) SubmitValidatorRegistrations(ctx context.Context,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) error {
	return s.submitValidatorRegistrationsForAccounts(ctx, accounts)
}

// submitValidatorRegistrations submits validator registrations.
func (s *Service) submitValidatorRegistrations(ctx context.Context) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "submitValidatorRegistrations")
	defer span.End()
	started := time.Now()

	// Only allow a single registration at a time.
	if !s.activitySem.TryAcquire(1) {
		s.log.Trace().Msg("Another validator registration submission in progress; skipping")
		return
	}
	defer s.activitySem.Release(1)

	epoch := s.chainTime.CurrentEpoch()

	// Fetch the validating accounts for the next epoch, to ensure that we capture any validators
	// that are going to start proposing soon.
	// Note that this will result in us not obtaining a validator that is on its last validating
	// epoch, however preparations linger for a couple of epochs after registration so this is safe.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch+1)
	if err != nil {
		monitorValidatorRegistrations(false, time.Since(started))
		s.log.Error().Err(err).Msg("Failed to obtain validating accounts")
		return
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	if len(accounts) == 0 {
		monitorValidatorRegistrations(false, time.Since(started))
		s.log.Debug().Msg("No validating accounts; not submiting validator registrations")
		return
	}
	if s.executionConfig == nil {
		monitorValidatorRegistrations(false, time.Since(started))
		s.log.Debug().Msg("No execution config; not submiting validator registrations")
		return
	}

	if err := s.submitValidatorRegistrationsForAccounts(ctx, accounts); err != nil {
		s.log.Error().Err(err).Msg("Failed to submit validator registrations")
	}

	monitorValidatorRegistrations(true, time.Since(started))
}

func (s *Service) submitValidatorRegistrationsForAccounts(ctx context.Context,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "submitValidatorRegistrationsForAccounts")
	defer span.End()

	if s.executionConfig == nil {
		return errors.New("no execution configuration; cannot submit validator registrations at current")
	}

	controlledValidators := make(map[phase0.BLSPubKey]struct{}, len(accounts))
	consensusRegistrations := make([]*consensusapi.VersionedSignedValidatorRegistration, 0, len(accounts))
	relayRegistrations := make(map[string][]*builderapi.VersionedSignedValidatorRegistration)
	for _, account := range accounts {
		accountConsensusRegistrations, err := s.generateValidatorRegistrationsForAccount(ctx,
			account,
			controlledValidators,
			relayRegistrations,
		)
		if err != nil {
			return err
		}
		consensusRegistrations = append(consensusRegistrations, accountConsensusRegistrations...)
	}
	span.AddEvent("Generated registrations")

	s.controlledValidatorsMu.Lock()
	s.controlledValidators = controlledValidators
	s.controlledValidatorsMu.Unlock()

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(relayRegistrations)
		if err == nil {
			e.RawJSON("registrations", data).Msg("Generated registrations")
		}
	}
	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(consensusRegistrations)
		if err == nil {
			e.RawJSON("registrations", data).Msg("Generated consensus registrations")
		}
	}

	s.submitRelayRegistrations(ctx, relayRegistrations)

	if len(consensusRegistrations) > 0 {
		s.submitConsensusRegistrations(ctx, consensusRegistrations)
	}

	return nil
}

func (s *Service) generateValidatorRegistrationsForAccount(ctx context.Context,
	account e2wtypes.Account,
	controlledValidators map[phase0.BLSPubKey]struct{},
	relayRegistrations map[string][]*builderapi.VersionedSignedValidatorRegistration,
) (
	[]*consensusapi.VersionedSignedValidatorRegistration,
	error,
) {
	pubkey := util.ValidatorPubkey(account)
	controlledValidators[pubkey] = struct{}{}

	proposerConfig, err := s.executionConfig.ProposerConfig(ctx, account, pubkey, s.fallbackFeeRecipient, s.fallbackGasLimit)
	if err != nil {
		return nil, errors.Wrap(err, "No proposer configuration; cannot submit validator registrations")
	}
	if proposerConfig.FeeRecipient.IsZero() {
		s.log.Error().Stringer("validator", pubkey).Msg("Received 0 execution address for validator registration; using fallback")
		proposerConfig.FeeRecipient = s.fallbackFeeRecipient
	}

	consensusRegistrations := make([]*consensusapi.VersionedSignedValidatorRegistration, 0, len(proposerConfig.Relays))

	for index, relay := range proposerConfig.Relays {
		relayRegistration, consensusRegistration, err := s.generateValidatorRegistrationForRelay(ctx, account, pubkey, relay)
		if err != nil {
			// Recognise the error but continue, to submit as many validator registrations as possible.
			s.log.Error().Str("relay", relay.Address).Err(err).Msg("Failed to generate registration; validator will not be registered with MEV relay")
			continue
		}
		if e := s.log.Trace(); e.Enabled() {
			data, err := json.Marshal(relayRegistration)
			if err == nil {
				e.Str("pubkey", fmt.Sprintf("%#x", pubkey)).Str("relay", relay.Address).RawJSON("registration", data).Msg("Registration")
			}
		}
		// Add the relay registration to the appropriate queue.
		if _, exists := relayRegistrations[relay.Address]; !exists {
			relayRegistrations[relay.Address] = make([]*builderapi.VersionedSignedValidatorRegistration, 0)
		}
		relayRegistrations[relay.Address] = append(relayRegistrations[relay.Address], relayRegistration)
		// We only add the first relay's consensus registration, as they are used purely to alert
		// the beacon node that the validator is expecting to use relays.
		if index == 0 {
			consensusRegistrations = append(consensusRegistrations, consensusRegistration)
		}
	}

	return consensusRegistrations, nil
}

func (s *Service) submitRelayRegistrations(ctx context.Context,
	relayRegistrations map[string][]*builderapi.VersionedSignedValidatorRegistration,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "submitRelayRegistrations")
	defer span.End()

	// Submit registrations in parallel to the builders.
	var wg sync.WaitGroup
	for builder, providerRegistrations := range relayRegistrations {
		wg.Add(1)
		go func(ctx context.Context, builder string, providerRegistrations []*builderapi.VersionedSignedValidatorRegistration, monitor metrics.Service) {
			defer wg.Done()
			ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "(submit relay registrations)", trace.WithAttributes(
				attribute.String("relay", builder),
			))
			defer span.End()

			client, err := util.FetchBuilderClient(ctx, builder, monitor, s.releaseVersion)
			if err != nil {
				s.log.Error().Err(err).Str("builder", builder).Msg("Failed to fetch builder client")
				return
			}
			submitter, isSubmitter := client.(builderclient.ValidatorRegistrationsSubmitter)
			if !isSubmitter {
				s.log.Error().Str("builder", builder).Msg("Builder client does not accept validator registrations")
				return
			}
			if err := submitter.SubmitValidatorRegistrations(ctx, &builderapi.SubmitValidatorRegistrationsOpts{
				// Validator registrations can take a long time, as they are processed sequentially by some relays.  As such,
				// unilaterally set the timeout here.  This code is within a waitgroup, so we're okay to wait for a little longer
				// than we would with most requests.
				Common: builderapi.CommonOpts{
					Timeout: time.Second * time.Duration(len(providerRegistrations)),
				},
				Registrations: providerRegistrations,
			}); err != nil {
				s.log.Error().Err(err).Str("builder", builder).Msg("Failed to submit validator registrations")
				return
			}
		}(ctx, builder, providerRegistrations, s.monitor)
	}
	wg.Wait()
}

func (s *Service) submitConsensusRegistrations(ctx context.Context,
	consensusRegistrations []*consensusapi.VersionedSignedValidatorRegistration,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "submitConsensusRegistrations")
	defer span.End()

	// Submit registrations in parallel to the beacon nodes.
	var wg sync.WaitGroup
	if len(consensusRegistrations) > 0 {
		for _, submitter := range s.secondaryValidatorRegistrationsSubmitters {
			wg.Add(1)
			go func(ctx context.Context, submitter eth2client.ValidatorRegistrationsSubmitter, registrations []*consensusapi.VersionedSignedValidatorRegistration) {
				defer wg.Done()
				ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "(submit consensus registrations)", trace.WithAttributes(
					attribute.String("node", submitter.(eth2client.Service).Address()),
				))
				defer span.End()

				s.log.Trace().Str("client", submitter.(eth2client.Service).Address()).Msg("Submitting secondary validator registrations")
				if err := submitter.SubmitValidatorRegistrations(ctx, registrations); err != nil {
					s.log.Error().Err(err).Str("client", submitter.(eth2client.Service).Address()).Msg("Failed to submit secondary validator registrations")
					return
				}
			}(ctx, submitter, consensusRegistrations)
		}
	}
	wg.Wait()
}

func (s *Service) generateValidatorRegistrationForRelay(ctx context.Context,
	account e2wtypes.Account,
	pubkey phase0.BLSPubKey,
	relayConfig *beaconblockproposer.RelayConfig,
) (
	*builderapi.VersionedSignedValidatorRegistration,
	*consensusapi.VersionedSignedValidatorRegistration,
	error,
) {
	// Create a registration without a timestamp, to allow matching its hash
	// with an existing registration (also registered without timestamp).
	registration := &apiv1.ValidatorRegistration{
		FeeRecipient: relayConfig.FeeRecipient,
		GasLimit:     relayConfig.GasLimit,
		Pubkey:       pubkey,
	}
	registrationRoot, err := registration.HashTreeRoot()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain hash tree root of registration")
	}
	// Now add the timestamp, for completeness of the struct.
	registration.Timestamp = time.Now().Round(time.Second)

	// See if we already have a signed registration that matches this configuration.
	s.signedValidatorRegistrationsMu.RLock()
	signedRegistration, exists := s.signedValidatorRegistrations[registrationRoot]
	s.signedValidatorRegistrationsMu.RUnlock()

	// See if the latest registration matches this configuration.
	s.latestValidatorRegistrationsMu.RLock()
	latestRoot := s.latestValidatorRegistrations[pubkey]
	s.latestValidatorRegistrationsMu.RUnlock()

	if exists && bytes.Equal(latestRoot[:], registrationRoot[:]) {
		monitorRegistrationsGeneration("cache")
	} else {
		s.log.Trace().Msg("Signing a new or updated validator registration")
		sig, err := s.validatorRegistrationSigner.SignValidatorRegistration(ctx, account, &builderapi.VersionedValidatorRegistration{
			Version: builderspec.BuilderVersionV1,
			V1:      registration,
		})
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to sign validator registration")
		}

		signedRegistration = &apiv1.SignedValidatorRegistration{
			Message:   registration,
			Signature: sig,
		}
		s.signedValidatorRegistrationsMu.Lock()
		s.signedValidatorRegistrations[registrationRoot] = signedRegistration
		s.signedValidatorRegistrationsMu.Unlock()
		s.latestValidatorRegistrationsMu.Lock()
		s.latestValidatorRegistrations[pubkey] = registrationRoot
		s.latestValidatorRegistrationsMu.Unlock()
		monitorRegistrationsGeneration("generation")
	}

	relayRegistration := &builderapi.VersionedSignedValidatorRegistration{
		Version: builderspec.BuilderVersionV1,
		V1:      signedRegistration,
	}

	consensusRegistration := &consensusapi.VersionedSignedValidatorRegistration{
		Version: consensusspec.BuilderVersionV1,
		V1: &consensusapiv1.SignedValidatorRegistration{
			Message: &consensusapiv1.ValidatorRegistration{
				FeeRecipient: signedRegistration.Message.FeeRecipient,
				GasLimit:     signedRegistration.Message.GasLimit,
				Timestamp:    signedRegistration.Message.Timestamp,
				Pubkey:       signedRegistration.Message.Pubkey,
			},
			Signature: signedRegistration.Signature,
		},
	}

	return relayRegistration, consensusRegistration, nil
}
