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
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/metrics"
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
	mutex                   sync.RWMutex
	monitor                 metrics.AccountManagerMonitor
	stores                  []e2wtypes.Store
	accountPaths            []string
	passphrases             [][]byte
	accounts                map[[48]byte]*ValidatingAccount
	validatorsProvider      eth2client.ValidatorsProvider
	slotsPerEpoch           uint64
	beaconProposerDomain    []byte
	beaconAttesterDomain    []byte
	randaoDomain            []byte
	selectionProofDomain    []byte
	aggregateAndProofDomain []byte
	signatureDomainProvider eth2client.SignatureDomainProvider
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
	beaconAttesterDomain, err := parameters.beaconAttesterDomainProvider.BeaconAttesterDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain beacon attester domain")
	}
	beaconProposerDomain, err := parameters.beaconProposerDomainProvider.BeaconProposerDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain beacon proposer domain")
	}
	randaoDomain, err := parameters.randaoDomainProvider.RANDAODomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain RANDAO domain")
	}
	selectionProofDomain, err := parameters.selectionProofDomainProvider.SelectionProofDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain selection proof domain")
	}
	aggregateAndProofDomain, err := parameters.aggregateAndProofDomainProvider.AggregateAndProofDomain(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain aggregate and proof domain")
	}
	s := &Service{
		monitor:                 parameters.monitor,
		stores:                  stores,
		accountPaths:            parameters.accountPaths,
		passphrases:             parameters.passphrases,
		validatorsProvider:      parameters.validatorsProvider,
		slotsPerEpoch:           slotsPerEpoch,
		beaconAttesterDomain:    beaconAttesterDomain,
		beaconProposerDomain:    beaconProposerDomain,
		randaoDomain:            randaoDomain,
		selectionProofDomain:    selectionProofDomain,
		aggregateAndProofDomain: aggregateAndProofDomain,
		signatureDomainProvider: parameters.signatureDomainProvider,
	}

	if err := s.RefreshAccounts(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch validating keys")
	}

	return s, nil
}

// UpdateAccountsState updates account state with the latest information from the beacon chain.
// This should be run at the beginning of each epoch to ensure that any newly-activated accounts are registered.
func (s *Service) UpdateAccountsState(ctx context.Context) error {
	validatorIDs := make([]eth2client.ValidatorIDProvider, 0, len(s.accounts))
	for _, account := range s.accounts {
		if !account.state.IsAttesting() {
			validatorIDs = append(validatorIDs, account)
		}
	}
	if len(validatorIDs) == 0 {
		// Nothing to do.
		log.Trace().Msg("No unactivated keys")
		return nil
	}
	validators, err := s.validatorsProvider.Validators(ctx, "head", validatorIDs)
	if err != nil {
		return errors.Wrap(err, "failed to obtain validators")
	}

	s.mutex.Lock()
	s.updateAccountStates(ctx, s.accounts, validators)
	s.mutex.Unlock()

	return nil
}

// RefreshAccounts refreshes the entire list of validating keys.
func (s *Service) RefreshAccounts(ctx context.Context) error {
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
	accounts := make(map[[48]byte]*ValidatingAccount)
	for _, wallet := range wallets {
		// if _, isProvider := wallet.(e2wtypes.WalletAccountsByPathProvider); isProvider {
		// 	fmt.Printf("TODO: fetch accounts by path")
		// } else {
		s.fetchAccountsForWallet(ctx, wallet, accounts, verificationRegexes)
		//}
	}

	validatorIDs := make([]eth2client.ValidatorIDProvider, 0, len(accounts))
	for _, account := range accounts {
		if !account.state.IsAttesting() {
			validatorIDs = append(validatorIDs, account)
		}
	}
	log.Trace().Int("keys", len(accounts)).Msg("Keys obtained")
	if len(validatorIDs) == 0 {
		log.Warn().Msg("No accounts obtained")
		return nil
	}

	validators, err := s.validatorsProvider.Validators(ctx, "head", validatorIDs)
	if err != nil {
		return errors.Wrap(err, "failed to obtain validators")
	}
	s.updateAccountStates(ctx, accounts, validators)

	s.mutex.Lock()
	s.accounts = accounts
	s.mutex.Unlock()

	return nil
}

// Accounts returns all attesting accounts.
func (s *Service) Accounts(ctx context.Context) ([]accountmanager.ValidatingAccount, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	accounts := make([]accountmanager.ValidatingAccount, 0, len(s.accounts))
	for _, account := range s.accounts {
		if account.state.IsAttesting() {
			accounts = append(accounts, account)
		}
	}

	return accounts, nil
}

// AccountsByIndex returns attesting accounts.
func (s *Service) AccountsByIndex(ctx context.Context, indices []uint64) ([]accountmanager.ValidatingAccount, error) {
	indexMap := make(map[uint64]bool)
	for _, index := range indices {
		indexMap[index] = true
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	accounts := make([]accountmanager.ValidatingAccount, 0, len(s.accounts))
	for _, account := range s.accounts {
		if !account.state.IsAttesting() {
			continue
		}
		index, err := account.Index(ctx)
		if err != nil {
			log.Error().Err(err).Msg("No index for account")
			continue
		}
		if _, exists := indexMap[index]; exists {
			accounts = append(accounts, account)

		}
	}

	return accounts, nil
}

// AccountsByPubKey returns validating accounts.
func (s *Service) AccountsByPubKey(ctx context.Context, pubKeys [][]byte) ([]accountmanager.ValidatingAccount, error) {
	pubKeyMap := make(map[[48]byte]bool)
	for _, pubKey := range pubKeys {
		var mapKey [48]byte
		copy(mapKey[:], pubKey)
		pubKeyMap[mapKey] = true
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	accounts := make([]accountmanager.ValidatingAccount, 0, len(s.accounts))
	for pubKey, account := range s.accounts {
		if !account.state.IsAttesting() {
			continue
		}
		if _, exists := pubKeyMap[pubKey]; exists {
			accounts = append(accounts, account)
		}
	}

	return accounts, nil
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

func (s *Service) updateAccountStates(ctx context.Context, accounts map[[48]byte]*ValidatingAccount, validators map[uint64]*api.Validator) {
	validatorsByPubKey := make(map[[48]byte]*api.Validator, len(validators))
	for _, validator := range validators {
		var pubKey [48]byte
		copy(pubKey[:], validator.Validator.PublicKey)
		validatorsByPubKey[pubKey] = validator
	}

	validatorStateCounts := make(map[string]uint64)
	for pubKey, account := range accounts {
		validator, exists := validatorsByPubKey[pubKey]
		if exists {
			account.index = validator.Index
			account.state = validator.State
		}
		validatorStateCounts[strings.ToLower(account.state.String())]++
	}
	for state, count := range validatorStateCounts {
		s.monitor.Accounts(state, count)
	}

	if e := log.Trace(); e.Enabled() {
		for _, account := range accounts {
			log.Trace().
				Str("name", account.account.Name()).
				Str("public_key", fmt.Sprintf("%x", account.account.PublicKey().Marshal())).
				Str("state", account.state.String()).
				Msg("Validating account")
		}
	}
}

func (s *Service) fetchAccountsForWallet(ctx context.Context, wallet e2wtypes.Wallet, accounts map[[48]byte]*ValidatingAccount, verificationRegexes []*regexp.Regexp) {
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
		accounts[bytesutil.ToBytes48(pubKey)] = &ValidatingAccount{
			account:                 account,
			accountManager:          s,
			signatureDomainProvider: s.signatureDomainProvider,
		}
	}
}
