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

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	// #nosec G108
	_ "net/http/pprof"
	"os"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	"github.com/spf13/viper"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	majordomo "github.com/wealdtech/go-majordomo"
)

// proposerConfigCheck checks a proposer configuration.
func proposerConfigCheck(ctx context.Context, majordomo majordomo.Service) bool {
	if err := e2types.InitBLS(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise BLS library: %v\n", err)
		return true
	}

	// Force disable metrics.
	viper.Set("metrics.prometheus.listen-address", "")
	consensusClient, chainTime, monitor, err := startBasicServices(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start basic services: %v\n", err)
		return true
	}

	validatorsManager, err := startValidatorsManager(ctx, monitor, consensusClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start validators manager: %v\n", err)
		return true
	}
	accountManager, err := startAccountManager(ctx, monitor, consensusClient, validatorsManager, majordomo, chainTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start account manager: %v\n", err)
		return true
	}
	scheduler := mockscheduler.New()
	signer, err := startSigner(ctx, monitor, consensusClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start signer: %v\n", err)
		return true
	}
	log.Trace().Msg("Starting cache")
	cacheSvc, err := startCache(ctx, monitor, chainTime, scheduler, consensusClient, consensusClient.(consensusclient.BeaconBlockHeadersProvider), consensusClient.(consensusclient.SignedBeaconBlockProvider))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start cache: %v\n", err)
		return true
	}

	blockRelaySvc, err := startBlockRelay(ctx, majordomo, monitor, consensusClient, scheduler, chainTime, accountManager, signer, cacheSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start block relay: %v\n", err)
		return true
	}

	// Set up the required account and pubkey.
	var pubkey phase0.BLSPubKey
	data, err := hex.DecodeString(strings.TrimPrefix(viper.GetString("proposer-config-check"), "0x"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid public key: %v\n", err)
		return true
	}
	copy(pubkey[:], data)
	account, err := accountManager.(accountmanager.AccountsProvider).AccountByPublicKey(ctx, pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not obtain account for public key: %v.  Please ensure the public key matches a validator managed by this Vouch instance.", err)
		return true
	}

	proposerConfig, err := blockRelaySvc.(blockrelay.ExecutionConfigProvider).ProposerConfig(ctx, account, pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to obtain proposer config: %v\n", err)
		return true
	}

	data, err = proposerConfig.MarshalJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid proposer config: %v\n", err)
		return true
	}

	fmt.Fprintf(os.Stdout, "%s\n", string(data))
	return true
}
