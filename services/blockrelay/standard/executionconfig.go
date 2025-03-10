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
	"net/http"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	httpconfidant "github.com/wealdtech/go-majordomo/confidants/http"
)

// fetchExecutionConfigRuntime sets the runtime for the next execution configuration call.
func (s *Service) fetchExecutionConfigRuntime(_ context.Context) (
	time.Time,
	error,
) {
	// Schedule for the middle of the slot, one-quarter through the epoch.
	currentEpoch := s.chainTime.CurrentEpoch()
	epochDuration := s.chainTime.StartOfEpoch(currentEpoch + 1).Sub(s.chainTime.StartOfEpoch(currentEpoch))
	currentSlot := s.chainTime.CurrentSlot()
	slotDuration := s.chainTime.StartOfSlot(currentSlot + 1).Sub(s.chainTime.StartOfSlot(currentSlot))
	offset := int(epochDuration.Seconds()/4.0 + slotDuration.Seconds()/2.0)
	return s.chainTime.StartOfEpoch(s.chainTime.CurrentEpoch() + 1).Add(time.Duration(offset) * time.Second), nil
}

// fetchExecutionConfig fetches the execution configuration.
func (s *Service) fetchExecutionConfig(ctx context.Context) {
	started := time.Now()
	epoch := s.chainTime.CurrentEpoch()

	// Fetch the validating accounts for the next epoch, to ensure that we capture any validators
	// that are going to start proposing soon.
	// Note that this will result in us not obtaining a validator that is on its last validating
	// epoch, however preparations linger for a couple of epochs after registration so this is safe.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch+1)
	if err != nil {
		monitorExecutionConfig(time.Since(started), false)
		s.log.Error().Err(err).Msg("Failed to obtain validating accounts; falling back")
		return
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	// Build list of public keys.
	pubkeys := make([]phase0.BLSPubKey, 0, len(accounts))
	for _, account := range accounts {
		pubkeys = append(pubkeys, util.ValidatorPubkey(account))
	}

	// Start with our current execution configuration.
	s.executionConfigMu.RLock()
	executionConfig := s.executionConfig
	s.executionConfigMu.RUnlock()

	if s.configURL == "" {
		s.log.Trace().Msg("No config URL; using default configuration with fallback")
	} else {
		succeeded := true
		// Obtain the execution configuration, handling errors appropriately.
		executionConfig, err = s.obtainExecutionConfig(ctx, pubkeys)
		if err != nil {
			succeeded = false
			s.log.Error().Str("config_url", s.configURL).Err(err).Msg("Failed to obtain execution configuration")
			// Restore current execution configuration.
			executionConfig = s.executionConfig
		} else if executionConfig == nil {
			succeeded = false
			s.log.Error().Str("config_url", s.configURL).Msg("Obtained nil execution configuration")
			// Restore current execution configuration.
			executionConfig = s.executionConfig
		}
		monitorExecutionConfig(time.Since(started), succeeded)
	}

	s.executionConfigMu.Lock()
	s.executionConfig = executionConfig
	s.executionConfigMu.Unlock()

	s.log.Trace().Msg("Obtained configuration")
}

func (s *Service) obtainExecutionConfig(ctx context.Context,
	pubkeys []phase0.BLSPubKey,
) (
	blockrelay.ExecutionConfigurator,
	error,
) {
	s.log.Trace().Msg("Obtaining execution configuration")

	var res []byte
	var err error
	if !strings.HasPrefix(s.configURL, "http") {
		// We are fetching from a static source.
		res, err = s.majordomo.Fetch(ctx, s.configURL)
	} else {
		// We are fetching from a dynamic source, need to provide additional parameters.
		if s.clientCertURL != "" {
			certPEMBlock, err := s.majordomo.Fetch(ctx, s.clientCertURL)
			if err != nil {
				return nil, errors.Wrap(err, "failed to obtain client certificate")
			}
			ctx = context.WithValue(ctx, &httpconfidant.ClientCert{}, certPEMBlock)
			keyPEMBlock, err := s.majordomo.Fetch(ctx, s.clientKeyURL)
			if err != nil {
				return nil, errors.Wrap(err, "failed to obtain client key")
			}
			ctx = context.WithValue(ctx, &httpconfidant.ClientKey{}, keyPEMBlock)
			var caPEMBlock []byte
			if s.caCertURL != "" {
				caPEMBlock, err = s.majordomo.Fetch(ctx, s.caCertURL)
				if err != nil {
					return nil, errors.Wrap(err, "failed to obtain client CA certificate")
				}
				ctx = context.WithValue(ctx, &httpconfidant.CACert{}, caPEMBlock)
			}
		}

		ctx = context.WithValue(ctx, &httpconfidant.HTTPMethod{}, http.MethodPost)
		ctx = context.WithValue(ctx, &httpconfidant.MIMEType{}, "application/json")
		body := pubKeysToArray(pubkeys)
		ctx = context.WithValue(ctx, &httpconfidant.Body{}, []byte(body))

		res, err = s.majordomo.Fetch(ctx, s.configURL)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain execution configuration")
	}

	s.log.Trace().RawJSON("res", bytes.ReplaceAll(res, []byte("\n"), []byte(""))).Msg("Received response")

	executionConfig, err := blockrelay.UnmarshalJSON(res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal execution config")
	}

	return executionConfig, nil
}

func pubKeysToArray(pubkeys []phase0.BLSPubKey) string {
	body := strings.Builder{}
	body.WriteString(`[`)
	for i, pubkey := range pubkeys {
		body.WriteString(`"`)
		body.WriteString(pubkey.String())
		body.WriteString(`"`)
		if i != len(pubkeys)-1 {
			body.WriteString(`,`)
		}
	}
	body.WriteString(`]`)

	return body.String()
}
