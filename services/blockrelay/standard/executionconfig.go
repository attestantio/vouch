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

package standard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	httpconfidant "github.com/wealdtech/go-majordomo/confidants/http"
)

var zeroFeeRecipient bellatrix.ExecutionAddress

// fetchExecutionConfigRuntime sets the runtime for the next execution configuration call.
func (s *Service) fetchExecutionConfigRuntime(_ context.Context,
	_ interface{},
) (
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
func (s *Service) fetchExecutionConfig(ctx context.Context,
	_ interface{},
) {
	started := time.Now()

	epoch := s.chainTime.CurrentEpoch()

	// Fetch the validating accounts for the next epoch, to ensure that we capture any validators
	// that are going to start proposing soon.
	// Note that this will result in us not obtaining a validator that is on its last validating
	// epoch, however preparations linger for a couple of epochs after registration so this is safe.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch+1)
	if err != nil {
		monitorExecutionConfig(time.Since(started), false)
		log.Error().Err(err).Msg("Failed to obtain validating accounts; falling back")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	if len(accounts) == 0 {
		monitorExecutionConfig(time.Since(started), false)
		log.Debug().Msg("No validating accounts; not fetching execution config")
	}

	// Build list of public keys.
	pubkeys := make([][]byte, 0, len(accounts))
	for _, account := range accounts {
		if provider, isProvider := account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
			pubkeys = append(pubkeys, provider.CompositePublicKey().Marshal())
		} else {
			pubkeys = append(pubkeys, account.PublicKey().Marshal())
		}
	}

	executionConfig, err := s.obtainExecutionConfig(ctx, pubkeys)
	if err != nil {
		monitorExecutionConfig(time.Since(started), false)
		if s.executionConfig == nil {
			log.Error().Err(err).Msg("Failed to obtain execution configuration; setting default configuration with fallback values from configuration")
			s.executionConfigMu.Lock()
			s.executionConfig = &blockrelay.ExecutionConfig{
				ProposerConfigs: make(map[phase0.BLSPubKey]*blockrelay.ProposerConfig),
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: s.fallbackFeeRecipient,
					GasLimit:     s.fallbackGasLimit,
					Builder:      &blockrelay.BuilderConfig{},
				},
			}
			s.executionConfigMu.Unlock()
		} else {
			log.Warn().Err(err).Msg("Failed to obtain updated execution configuration; retaining current configuration")
		}
		return
	}
	if executionConfig == nil {
		monitorExecutionConfig(time.Since(started), false)
		if s.executionConfig == nil {
			log.Error().Err(err).Msg("Obtained nil execution configuration; setting default configuration with fallback values from configuration")
			s.executionConfigMu.Lock()
			s.executionConfig = &blockrelay.ExecutionConfig{
				ProposerConfigs: make(map[phase0.BLSPubKey]*blockrelay.ProposerConfig),
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: s.fallbackFeeRecipient,
					GasLimit:     s.fallbackGasLimit,
					Builder:      &blockrelay.BuilderConfig{},
				},
			}
			s.executionConfigMu.Unlock()
		} else {
			log.Warn().Err(err).Msg("Obtained nil updated execution configuration; retaining current configuration")
		}
		return
	}

	s.normaliseExecutionConfig(ctx, executionConfig)

	log.Trace().Stringer("execution_config", executionConfig).Msg("Obtained configuration")

	s.executionConfigMu.Lock()
	s.executionConfig = executionConfig
	s.executionConfigMu.Unlock()

	monitorExecutionConfig(time.Since(started), true)

	log.Trace().Int("execution configs", len(s.executionConfig.ProposerConfigs)).Msg("Obtained execution configuration")
}

func (s *Service) obtainExecutionConfig(ctx context.Context,
	pubkeys [][]byte,
) (
	*blockrelay.ExecutionConfig,
	error,
) {
	log.Trace().Msg("Obtaining execution configuration")

	var res []byte
	var err error
	if !strings.HasPrefix(s.configURL, "http") {
		// We are fetching from a static source.
		res, err = s.majordomo.Fetch(ctx, s.configURL)
	} else {
		// We are fetching from a dynamic source, need to provide additional parameters.
		if len(pubkeys) == 0 {
			// No results, but no error.
			log.Trace().Msg("no public keys supplied; cannot fetch execution configuation")
			return nil, nil
		}

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
		pubkeyStrs := make([]string, 0, len(pubkeys))
		for _, pubkey := range pubkeys {
			pubkeyStrs = append(pubkeyStrs, fmt.Sprintf("%#x", pubkey))
		}
		ctx = context.WithValue(ctx, &httpconfidant.Body{}, []byte(fmt.Sprintf(`["%s"]`, strings.Join(pubkeyStrs, `","`))))

		res, err = s.majordomo.Fetch(ctx, s.configURL)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain execution configuration")
	}

	log.Trace().Str("res", string(res)).Msg("Received response")

	executionConfig := &blockrelay.ExecutionConfig{}
	if err := json.Unmarshal(res, executionConfig); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal execution config")
	}

	return executionConfig, nil
}

// ExecutionConfig provides the current execution configuration.
func (s *Service) ExecutionConfig(_ context.Context) (*blockrelay.ExecutionConfig, error) {
	s.executionConfigMu.RLock()
	defer s.executionConfigMu.RUnlock()
	if s.executionConfig == nil {
		return nil, errors.New("no execution config available at current")
	}
	return s.executionConfig, nil
}

// normaliseExecutionConfig tidies up potentially partially missing execution configuration values.
func (s *Service) normaliseExecutionConfig(_ context.Context,
	executionConfig *blockrelay.ExecutionConfig,
) {
	// Ensure that missing default values are filled with fallbacks.
	if executionConfig.DefaultConfig == nil {
		executionConfig.DefaultConfig = &blockrelay.ProposerConfig{}
	}
	if executionConfig.DefaultConfig.GasLimit == 0 {
		log.Debug().Msg("Default gas limit 0; setting to fallback value")
		executionConfig.DefaultConfig.GasLimit = s.fallbackGasLimit
	}
	if bytes.Equal(executionConfig.DefaultConfig.FeeRecipient[:], zeroFeeRecipient[:]) {
		log.Debug().Msg("Default fee recipient 0; setting to fallback value")
		executionConfig.DefaultConfig.FeeRecipient = s.fallbackFeeRecipient
	}
	if executionConfig.DefaultConfig.Builder == nil {
		executionConfig.DefaultConfig.Builder = &blockrelay.BuilderConfig{}
	}
	// Ensure that missing proposer values are filled with defaults.
	for key, proposerConfig := range executionConfig.ProposerConfigs {
		if proposerConfig == nil {
			proposerConfig = &blockrelay.ProposerConfig{}
			executionConfig.ProposerConfigs[key] = proposerConfig
		}
		if proposerConfig.GasLimit == 0 {
			log.Debug().Str("validator", fmt.Sprintf("%#x", key)).Msg("Gas limit 0; setting to default value")
			proposerConfig.GasLimit = executionConfig.DefaultConfig.GasLimit
		}
		if bytes.Equal(proposerConfig.FeeRecipient[:], zeroFeeRecipient[:]) {
			log.Debug().Str("validator", fmt.Sprintf("%#x", key)).Msg("Fee recipient 0; setting to default value")
			proposerConfig.FeeRecipient = executionConfig.DefaultConfig.FeeRecipient
		}
		if proposerConfig.Builder == nil {
			proposerConfig.Builder = executionConfig.DefaultConfig.Builder
		}
	}
}
