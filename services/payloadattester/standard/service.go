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

package standard

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the standard payload attester.
type Service struct {
	log                                 zerolog.Logger
	monitor                             metrics.Service
	payloadAttestationDataProvider      eth2client.PayloadAttestationDataProvider
	payloadAttestationDataSigner        signer.PayloadAttestationDataSigner
	payloadAttestationMessagesSubmitter submitter.PayloadAttestationMessagesSubmitter
}

// New creates a new payload attester.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}
	log := zerologger.With().Str("service", "payloadattester").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}
	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}
	return &Service{
		log:                                 log,
		monitor:                             parameters.monitor,
		payloadAttestationDataProvider:      parameters.payloadAttestationDataProvider,
		payloadAttestationDataSigner:        parameters.payloadAttestationDataSigner,
		payloadAttestationMessagesSubmitter: parameters.payloadAttestationMessagesSubmitter,
	}, nil
}

// Prepare records a scheduled payload attestation duty.
func (s *Service) Prepare(_ context.Context, duty *payloadattester.Duty) error {
	if duty == nil {
		return nil
	}
	count := len(duty.ValidatorIndices())
	monitorPayloadAttestationProcess("scheduled", count)
	s.log.Trace().Uint64("slot", uint64(duty.Slot())).Int("count", count).Msg("Scheduled payload attestations")

	return nil
}

// Attest creates and submits payload attestation messages.
func (s *Service) Attest(ctx context.Context, duty *payloadattester.Duty) ([]*spec.VersionedPayloadAttestationMessage, error) {
	if duty == nil {
		return nil, errors.New("no duty supplied")
	}
	started := time.Now()

	accounts := make([]e2wtypes.Account, 0, len(duty.ValidatorIndices()))
	indices := make([]phase0.ValidatorIndex, 0, len(duty.ValidatorIndices()))
	for _, index := range duty.ValidatorIndices() {
		account := duty.Account(index)
		if account == nil {
			continue
		}
		accounts = append(accounts, account)
		indices = append(indices, index)
	}
	if len(accounts) == 0 {
		return []*spec.VersionedPayloadAttestationMessage{}, nil
	}

	response, err := s.payloadAttestationDataProvider.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: duty.Slot()})
	if err != nil {
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to produce payload attestation data")
		return nil, errors.Wrap(err, "failed to obtain payload attestation data")
	}
	if response == nil || response.Data == nil {
		err := errors.New("no payload attestation data returned")
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to produce payload attestation data")
		return nil, err
	}
	if response.Data.Version != spec.DataVersionGloas || response.Data.Gloas == nil {
		err := errors.New("payload attestation data is not Gloas")
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to produce payload attestation data")
		return nil, err
	}
	data := response.Data.Gloas
	if data.Slot != duty.Slot() {
		err := errors.Errorf("payload attestation data slot %d does not match duty slot %d", data.Slot, duty.Slot())
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to produce payload attestation data")
		return nil, err
	}
	monitorPayloadAttestationProcess("produced", len(accounts))
	s.log.Trace().Uint64("slot", uint64(duty.Slot())).Dur("elapsed", time.Since(started)).Msg("Produced payload attestation data")

	signatures, err := s.payloadAttestationDataSigner.SignPayloadAttestationData(ctx, accounts, data)
	if err != nil {
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to sign payload attestation data")
		return nil, errors.Wrap(err, "failed to sign payload attestation data")
	}
	if len(signatures) != len(accounts) {
		err := errors.New("number of payload attestation signatures does not match number of accounts")
		monitorPayloadAttestationProcess("failed", len(accounts))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to sign payload attestation data")
		return nil, err
	}
	monitorPayloadAttestationProcess("signed", len(accounts))
	s.log.Trace().Uint64("slot", uint64(duty.Slot())).Int("count", len(accounts)).Dur("elapsed", time.Since(started)).Msg("Signed payload attestation messages")

	messages := make([]*spec.VersionedPayloadAttestationMessage, len(accounts))
	for i := range accounts {
		messages[i] = &spec.VersionedPayloadAttestationMessage{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.PayloadAttestationMessage{
				ValidatorIndex: indices[i],
				Data:           data,
				Signature:      signatures[i],
			},
		}
	}
	if err := s.payloadAttestationMessagesSubmitter.SubmitPayloadAttestationMessages(ctx, &api.SubmitPayloadAttestationMessagesOpts{Messages: messages}); err != nil {
		monitorPayloadAttestationProcess("failed", len(messages))
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to submit payload attestation messages")
		return nil, errors.Wrap(err, "failed to submit payload attestation messages")
	}
	monitorPayloadAttestationProcess("submitted", len(messages))
	s.log.Trace().Uint64("slot", uint64(duty.Slot())).Int("count", len(messages)).Dur("elapsed", time.Since(started)).Msg("Submitted payload attestation messages")

	return messages, nil
}
