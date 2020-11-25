// Copyright © 2020 Attestant Limited.
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

package wallet

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-bytesutil"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the manager for wallet accounts.
type Service struct {
	mutex             sync.RWMutex
	monitor           metrics.AccountManagerMonitor
	stores            []e2wtypes.Store
	accountPaths      []string
	passphrases       [][]byte
	accounts          map[spec.BLSPubKey]e2wtypes.Account
	validatorsManager validatorsmanager.Service
	slotsPerEpoch     spec.Slot
	domainProvider    eth2client.DomainProvider
	farFutureEpoch    spec.Epoch
}

// module-wide log.
var log zerolog.Logger

// New creates a new wallet account manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "accountmanager").Str("impl", "wallet").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	// Warn about lack of slashing protection
	log.Warn().Msg("The wallet account manager does not provide built-in slashing protection.  Please use the dirk account manager for production systems.")

	stores := make([]e2wtypes.Store, 0, len(parameters.locations))
	if len(parameters.locations) == 0 {
		// Use default location.
		stores = append(stores, filesystem.New())
	} else {
		for _, location := range parameters.locations {
			stores = append(stores, filesystem.New(filesystem.WithLocation(location)))
		}
	}

	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slots per epoch")
	}
	farFutureEpoch, err := parameters.farFutureEpochProvider.FarFutureEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain far future epoch")
	}

	s := &Service{
		monitor:           parameters.monitor,
		stores:            stores,
		accountPaths:      parameters.accountPaths,
		passphrases:       parameters.passphrases,
		validatorsManager: parameters.validatorsManager,
		slotsPerEpoch:     spec.Slot(slotsPerEpoch),
		domainProvider:    parameters.domainProvider,
		farFutureEpoch:    farFutureEpoch,
	}

	if err := s.refreshAccounts(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch accounts")
	}
	if err := s.refreshValidators(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch validator states")
	}

	return s, nil
}

// Refresh refreshes the accounts from local store, and account validator state from
// the validators provider.
// This is a relatively expensive operation, so should not be run in the validating path.
func (s *Service) Refresh(ctx context.Context) {
	if err := s.refreshAccounts(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to refresh accounts")
	}
	if err := s.refreshValidators(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to refresh validators")
	}
}

// refreshAccounts refreshes the accounts from local store.
func (s *Service) refreshAccounts(ctx context.Context) error {
	// Find the relevant wallets.
	wallets := make(map[string]e2wtypes.Wallet)
	pathsByWallet := make(map[string][]string)
	for _, path := range s.accountPaths {
		pathBits := strings.Split(path, "/")

		var paths []string
		var exists bool
		if paths, exists = pathsByWallet[pathBits[0]]; !exists {
			paths = make([]string, 0)
		}
		pathsByWallet[pathBits[0]] = append(paths, path)
		// Try each store in turn.
		found := false
		for _, store := range s.stores {
			wallet, err := e2wallet.OpenWallet(pathBits[0], e2wallet.WithStore(store))
			if err == nil {
				wallets[wallet.Name()] = wallet
				found = true
				break
			}
		}
		if !found {
			log.Warn().Str("wallet", pathBits[0]).Msg("Failed to find wallet in any store")
		}
	}

	verificationRegexes := accountPathsToVerificationRegexes(s.accountPaths)
	// Fetch accounts for each wallet.
	accounts := make(map[spec.BLSPubKey]e2wtypes.Account)
	for _, wallet := range wallets {
		// if _, isProvider := wallet.(e2wtypes.WalletAccountsByPathProvider); isProvider {
		// 	fmt.Printf("TODO: fetch accounts by path")
		// } else {
		s.fetchAccountsForWallet(ctx, wallet, accounts, verificationRegexes)
		//}
	}
	log.Trace().Int("accounts", len(accounts)).Msg("Obtained accounts")

	s.mutex.Lock()
	s.accounts = accounts
	s.mutex.Unlock()

	return nil
}

// refreshValidators refreshes the validator information for our known accounts.
func (s *Service) refreshValidators(ctx context.Context) error {
	accountPubKeys := make([]spec.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		accountPubKeys = append(accountPubKeys, pubKey)
	}
	if err := s.validatorsManager.RefreshValidatorsFromBeaconNode(ctx, accountPubKeys); err != nil {
		return errors.Wrap(err, "failed to refresh validators")
	}
	return nil
}

// ValidatingAccountsForEpoch obtains the validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpoch(ctx context.Context, epoch spec.Epoch) (map[spec.ValidatorIndex]e2wtypes.Account, error) {
	validatingAccounts := make(map[spec.ValidatorIndex]e2wtypes.Account)
	pubKeys := make([]spec.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		pubKeys = append(pubKeys, pubKey)
	}

	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	for index, validator := range validators {
		state := api.ValidatorToState(validator, epoch, s.farFutureEpoch)
		if state == api.ValidatorStateActiveOngoing || state == api.ValidatorStateActiveExiting {
			validatingAccounts[index] = s.accounts[validator.PublicKey]
		}
	}

	return validatingAccounts, nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpochByIndex(ctx context.Context, epoch spec.Epoch, indices []spec.ValidatorIndex) (map[spec.ValidatorIndex]e2wtypes.Account, error) {
	validatingAccounts := make(map[spec.ValidatorIndex]e2wtypes.Account)
	pubKeys := make([]spec.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		pubKeys = append(pubKeys, pubKey)
	}

	indexPresenceMap := make(map[spec.ValidatorIndex]bool)
	for _, index := range indices {
		indexPresenceMap[index] = true
	}
	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	for index, validator := range validators {
		if _, present := indexPresenceMap[index]; !present {
			continue
		}
		state := api.ValidatorToState(validator, epoch, s.farFutureEpoch)
		if state == api.ValidatorStateActiveOngoing || state == api.ValidatorStateActiveExiting {
			validatingAccounts[index] = s.accounts[validator.PublicKey]
		}
	}

	return validatingAccounts, nil
}

// accountPathsToVerificationRegexes turns account paths in to regexes to allow verification.
func accountPathsToVerificationRegexes(paths []string) []*regexp.Regexp {
	regexes := make([]*regexp.Regexp, 0, len(paths))
	for _, path := range paths {
		log := log.With().Str("path", path).Logger()
		parts := strings.Split(path, "/")
		if len(parts) == 0 || len(parts[0]) == 0 {
			log.Debug().Msg("Invalid path")
			continue
		}
		if len(parts) == 1 {
			parts = append(parts, ".*")
		}
		parts[1] = strings.TrimPrefix(parts[1], "^")
		var specifier string
		if strings.HasSuffix(parts[1], "$") {
			specifier = fmt.Sprintf("^%s/%s", parts[0], parts[1])
		} else {
			specifier = fmt.Sprintf("^%s/%s$", parts[0], parts[1])
		}
		regex, err := regexp.Compile(specifier)
		if err != nil {
			log.Warn().Str("specifier", specifier).Err(err).Msg("Invalid path regex")
			continue
		}
		regexes = append(regexes, regex)
	}
	return regexes
}

func (s *Service) fetchAccountsForWallet(ctx context.Context, wallet e2wtypes.Wallet, accounts map[spec.BLSPubKey]e2wtypes.Account, verificationRegexes []*regexp.Regexp) {
	for account := range wallet.Accounts(ctx) {
		// Ensure the name matches one of our account paths.
		name := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
		verified := false
		for _, verificationRegex := range verificationRegexes {
			if verificationRegex.Match([]byte(name)) {
				verified = true
				break
			}
		}
		if !verified {
			log.Debug().Str("account", name).Msg("Received unwanted account from server; ignoring")
			continue
		}

		var pubKey []byte
		if provider, isProvider := account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
			pubKey = provider.CompositePublicKey().Marshal()
		} else {
			pubKey = account.PublicKey().Marshal()
		}

		// Ensure we can unlock the account with a known passphrase.
		if unlocker, isUnlocker := account.(e2wtypes.AccountLocker); isUnlocker {
			unlocked := false
			for _, passphrase := range s.passphrases {
				if err := unlocker.Unlock(ctx, passphrase); err == nil {
					unlocked = true
					break
				}
			}
			if !unlocked {
				log.Warn().Str("account", name).Msg("Failed to unlock account with any passphrase")
				continue
			}
		}

		// Set up account as unknown to beacon chain.
		accounts[bytesutil.ToBytes48(pubKey)] = account
	}
}
