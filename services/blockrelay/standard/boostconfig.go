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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	httpconfidant "github.com/wealdtech/go-majordomo/confidants/http"
)

// fetchBoostConfigRuntime sets the runtime for the next boost configuration call.
func (s *Service) fetchBoostConfigRuntime(_ context.Context,
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

// fetchBoostConfig fetches the boost configuration.
func (s *Service) fetchBoostConfig(ctx context.Context,
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
		monitorBoostConfig(time.Since(started), false)
		log.Error().Err(err).Msg("Failed to obtain validating accounts")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	if len(accounts) == 0 {
		monitorBoostConfig(time.Since(started), false)
		log.Debug().Msg("No validating accounts; not fetching boost config")
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

	boostConfig, err := s.obtainBoostConfig(ctx, pubkeys)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain boost configuration")
	}
	if boostConfig == nil {
		monitorBoostConfig(time.Since(started), false)
		log.Error().Msg("Obtained nil boost configuration")
		return
	}

	log.Trace().Stringer("boost_config", boostConfig).Msg("Obtained configuration")

	s.boostConfigMu.Lock()
	s.boostConfig = boostConfig
	s.boostConfigMu.Unlock()

	monitorBoostConfig(time.Since(started), true)

	log.Trace().Int("proposer configs", len(s.boostConfig.ProposerConfigs)).Msg("Obtained boost configuration")
}

func (s *Service) obtainBoostConfig(ctx context.Context,
	pubkeys [][]byte,
) (
	*blockrelay.BoostConfig,
	error,
) {
	log.Info().Msg("Obtaining boost configuration")

	if len(pubkeys) == 0 {
		// No results, but no error.
		log.Trace().Msg("no public keys supplied; cannot fetch boost configuation")
		return nil, nil
	}

	certPEMBlock, err := s.majordomo.Fetch(ctx, viper.GetString("blockrelay.config.client-cert"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	ctx = context.WithValue(ctx, &httpconfidant.ClientCert{}, certPEMBlock)
	keyPEMBlock, err := s.majordomo.Fetch(ctx, viper.GetString("blockrelay.config.client-key"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server key")
	}
	ctx = context.WithValue(ctx, &httpconfidant.ClientKey{}, keyPEMBlock)
	var caPEMBlock []byte
	if viper.GetString("blockrelay.config.ca-cert") != "" {
		caPEMBlock, err = s.majordomo.Fetch(ctx, viper.GetString("blockrelay.config.ca-cert"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain client CA certificate")
		}
		ctx = context.WithValue(ctx, &httpconfidant.CACert{}, caPEMBlock)
	}

	ctx = context.WithValue(ctx, &httpconfidant.HTTPMethod{}, http.MethodPost)

	pubkeyStrs := make([]string, 0, len(pubkeys))
	for _, pubkey := range pubkeys {
		pubkeyStrs = append(pubkeyStrs, fmt.Sprintf("%#x", pubkey))
	}
	ctx = context.WithValue(ctx, &httpconfidant.Body{}, []byte(fmt.Sprintf(`["%s"]`, strings.Join(pubkeyStrs, `","`))))

	res, err := s.majordomo.Fetch(ctx, fmt.Sprintf("%s/config", s.configBaseURL))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain boost configuration")
	}

	log.Info().Str("res", string(res)).Msg("Received response")

	boostConfig := &blockrelay.BoostConfig{}
	if err := json.Unmarshal(res, boostConfig); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal boost config")
	}

	return boostConfig, nil
}
