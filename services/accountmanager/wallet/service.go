// Copyright © 2020 - 2025 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager/utils"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// Service is the manager for wallet accounts.
type Service struct {
	log                  zerolog.Logger
	mutex                sync.RWMutex
	monitor              metrics.Service
	processConcurrency   int64
	stores               []e2wtypes.Store
	accountPaths         []string
	passphrases          [][]byte
	accounts             map[phase0.BLSPubKey]e2wtypes.Account
	validatorsManager    validatorsmanager.Service
	slotsPerEpoch        phase0.Slot
	domainProvider       eth2client.DomainProvider
	farFutureEpoch       phase0.Epoch
	currentEpochProvider chaintime.Service
}

// New creates a new wallet account manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "accountmanager").Str("impl", "wallet").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := utils.RegisterMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	// Warn about lack of slashing protection
	log.Warn().Msg("The wallet account manager does not provide built-in slashing protection.  Please use the dirk account manager for production systems.")

	stores := make([]e2wtypes.Store, 0, len(parameters.locations))
	if len(parameters.locations) == 0 {
		log.Trace().Msg("No custom wallet locations provided; using wallet store with default location")
		stores = append(stores, filesystem.New())
	} else {
		for _, location := range parameters.locations {
			log.Trace().Str("location", location).Msg("Adding wallet store with user-supplied location")
			stores = append(stores, filesystem.New(filesystem.WithLocation(location)))
		}
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("failed to obtain SLOTS_PER_EPOCH")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	farFutureEpoch, err := parameters.farFutureEpochProvider.FarFutureEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain far future epoch")
	}

	s := &Service{
		log:                  log,
		monitor:              parameters.monitor,
		processConcurrency:   parameters.processConcurrency,
		stores:               stores,
		accountPaths:         parameters.accountPaths,
		passphrases:          parameters.passphrases,
		validatorsManager:    parameters.validatorsManager,
		slotsPerEpoch:        phase0.Slot(slotsPerEpoch),
		domainProvider:       parameters.domainProvider,
		farFutureEpoch:       farFutureEpoch,
		currentEpochProvider: parameters.currentEpochProvider,
	}

	s.refreshAccounts(ctx)
	if err := s.refreshValidators(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch validator states")
	}

	return s, nil
}

// Refresh refreshes the accounts from local store, and account validator state from
// the validators provider.
// This is a relatively expensive operation, so should not be run in the validating path.
func (s *Service) Refresh(ctx context.Context) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, "Refresh")
	defer span.End()

	s.refreshAccounts(ctx)
	if err := s.refreshValidators(ctx); err != nil {
		s.log.Error().Err(err).Msg("Failed to refresh validators")
	}
}

// refreshAccounts refreshes the accounts from local store.
func (s *Service) refreshAccounts(ctx context.Context) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, "refreshAccounts")
	defer span.End()

	// Find the relevant wallets.
	wallets := make(map[string]e2wtypes.Wallet)
	for _, path := range s.accountPaths {
		pathBits := strings.Split(path, "/")

		// Try each store in turn.
		found := false
		for _, store := range s.stores {
			s.log.Trace().Str("store", store.Name()).Str("wallet", pathBits[0]).Msg("Checking for wallet in store")
			wallet, err := e2wallet.OpenWallet(pathBits[0], e2wallet.WithStore(store))
			if err == nil {
				s.log.Trace().Str("store", store.Name()).Str("wallet", pathBits[0]).Msg("Found wallet in store")
				wallets[wallet.Name()] = wallet
				found = true
				break
			}
			s.log.Trace().Str("store", store.Name()).Str("wallet", pathBits[0]).Err(err).Msg("Failed to find wallet in store")
		}
		if !found {
			s.log.Warn().Str("wallet", pathBits[0]).Msg("Failed to find wallet in any store")
		}
	}
	if e := s.log.Trace(); e.Enabled() {
		walletNames := make([]string, 0, len(wallets))
		for walletName := range wallets {
			walletNames = append(walletNames, walletName)
			e.Strs("wallets", walletNames).Msg("Refreshing wallets")
		}
	}

	verificationRegexes := s.accountPathsToVerificationRegexes(s.accountPaths)
	// Fetch accounts for each wallet.
	accounts := make(map[phase0.BLSPubKey]e2wtypes.Account)
	for _, wallet := range wallets {
		s.fetchAccountsForWallet(ctx, wallet, accounts, verificationRegexes)
	}
	s.log.Trace().Int("accounts", len(accounts)).Msg("Obtained accounts")

	s.mutex.Lock()
	s.accounts = accounts
	s.mutex.Unlock()
}

// refreshValidators refreshes the validator information for our known accounts.
func (s *Service) refreshValidators(ctx context.Context) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, "refreshValidators")
	defer span.End()

	accountPubKeys := make([]phase0.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		accountPubKeys = append(accountPubKeys, pubKey)
	}
	if err := s.validatorsManager.RefreshValidatorsFromBeaconNode(ctx, accountPubKeys); err != nil {
		return errors.Wrap(err, "failed to refresh validators")
	}
	return nil
}

// ValidatingAccountsForEpoch obtains the validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpoch(ctx context.Context, epoch phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	filterFunc := func(state apiv1.ValidatorState) bool {
		return state == apiv1.ValidatorStateActiveOngoing || state == apiv1.ValidatorStateActiveExiting
	}
	return s.accountsForEpochWithFilter(ctx, epoch, "Validating", filterFunc)
}

// SyncCommitteeAccountsForEpoch obtains the accounts eligible for Sync Committee duty for a given epoch.
// The Ethereum specification has different criteria for Sync Committee eligibility compared to other validating duties.
// This includes an edge case where we are still in scope for sync committee duty between exited and withdrawal states.
func (s *Service) SyncCommitteeAccountsForEpoch(ctx context.Context, epoch phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return s.accountsForEpochWithFilter(ctx, epoch, "SyncCommittee", utils.IsSyncCommitteeEligible)
}

// accountsForEpochWithFilter obtains the accounts for a given epoch with a filter on the state of validators returned.
func (s *Service) accountsForEpochWithFilter(ctx context.Context, epoch phase0.Epoch, accountType string, filterFunc func(state apiv1.ValidatorState) bool) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, fmt.Sprintf("%sAccountsForEpoch", accountType), trace.WithAttributes(
		attribute.Int64("epoch", util.EpochToInt64(epoch)),
	))
	defer span.End()

	// stateCount is used to update metrics.
	stateCount := map[apiv1.ValidatorState]uint64{
		apiv1.ValidatorStateUnknown:            0,
		apiv1.ValidatorStatePendingInitialized: 0,
		apiv1.ValidatorStatePendingQueued:      0,
		apiv1.ValidatorStateActiveOngoing:      0,
		apiv1.ValidatorStateActiveExiting:      0,
		apiv1.ValidatorStateActiveSlashed:      0,
		apiv1.ValidatorStateExitedUnslashed:    0,
		apiv1.ValidatorStateExitedSlashed:      0,
		apiv1.ValidatorStateWithdrawalPossible: 0,
		apiv1.ValidatorStateWithdrawalDone:     0,
	}

	validatingAccounts := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	pubKeys := make([]phase0.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		pubKeys = append(pubKeys, pubKey)
	}

	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	for index, validator := range validators {
		state := apiv1.ValidatorToState(validator, nil, epoch, s.farFutureEpoch)
		stateCount[state]++
		if filterFunc(state) {
			account := s.accounts[validator.PublicKey]
			s.log.Trace().
				Str("name", account.Name()).
				Str("public_key", fmt.Sprintf("%x", account.PublicKey().Marshal())).
				Uint64("index", uint64(index)).
				Str("state", state.String()).
				Msg(fmt.Sprintf("%s account", accountType))
			validatingAccounts[index] = account
		}
	}

	// Update metrics if this is the current epoch.
	if epoch == s.currentEpochProvider.CurrentEpoch() {
		stateCount[apiv1.ValidatorStateUnknown] += util.IntToUint64(len(s.accounts) - len(validators))
		for state, count := range stateCount {
			utils.MonitorAccounts(strings.ToLower(state.String()), count)
		}
	}

	return validatingAccounts, nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpochByIndex(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	filterFunc := func(state apiv1.ValidatorState) bool {
		return state == apiv1.ValidatorStateActiveOngoing || state == apiv1.ValidatorStateActiveExiting
	}
	return s.accountsForEpochByIndexWithFilter(ctx, epoch, indices, "Validating", filterFunc)
}

// SyncCommitteeAccountsForEpochByIndex obtains the specified Sync Committee eligible accounts for a given epoch.
// The Ethereum specification has different criteria for Sync Committee eligibility compared to other validating duties.
// This includes an edge case where we are still in scope for sync committee duty between exited and withdrawal states.
func (s *Service) SyncCommitteeAccountsForEpochByIndex(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return s.accountsForEpochByIndexWithFilter(ctx, epoch, indices, "SyncCommittee", utils.IsSyncCommitteeEligible)
}

// accountsForEpochByIndexWithFilter obtains the specified accounts for a given epoch with a filter on the state of validators returned.
func (s *Service) accountsForEpochByIndexWithFilter(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex, accountType string, filterFunc func(state apiv1.ValidatorState) bool) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, fmt.Sprintf("%sAccountsForEpochByIndex", accountType), trace.WithAttributes(
		attribute.Int64("epoch", util.EpochToInt64(epoch)),
	))
	defer span.End()

	validatingAccounts := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	pubKeys := make([]phase0.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		pubKeys = append(pubKeys, pubKey)
	}

	indexPresenceMap := make(map[phase0.ValidatorIndex]bool)
	for _, index := range indices {
		indexPresenceMap[index] = true
	}
	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	for index, validator := range validators {
		if _, present := indexPresenceMap[index]; !present {
			continue
		}
		state := apiv1.ValidatorToState(validator, nil, epoch, s.farFutureEpoch)
		if filterFunc(state) {
			validatingAccounts[index] = s.accounts[validator.PublicKey]
		}
	}

	return validatingAccounts, nil
}

// accountPathsToVerificationRegexes turns account paths in to regexes to allow verification.
func (s *Service) accountPathsToVerificationRegexes(paths []string) []*regexp.Regexp {
	regexes := make([]*regexp.Regexp, 0, len(paths))
	for _, path := range paths {
		log := s.log.With().Str("path", path).Logger()
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
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

func (s *Service) fetchAccountsForWallet(ctx context.Context, wallet e2wtypes.Wallet, accounts map[phase0.BLSPubKey]e2wtypes.Account, verificationRegexes []*regexp.Regexp) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.wallet").Start(ctx, "fetchAccountsForWallet", trace.WithAttributes(
		attribute.String("wallet", wallet.Name()),
	))
	defer span.End()

	var mu sync.Mutex
	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for account := range wallet.Accounts(ctx) {
		wg.Add(1)
		go func(ctx context.Context, sem *semaphore.Weighted, wg *sync.WaitGroup, wallet e2wtypes.Wallet, account e2wtypes.Account, accounts map[phase0.BLSPubKey]e2wtypes.Account, mu *sync.Mutex) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				s.log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)
			// Ensure the name matches one of our account paths.
			name := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
			verified := false
			for _, verificationRegex := range verificationRegexes {
				if verificationRegex.MatchString(name) {
					verified = true
					break
				}
			}
			if !verified {
				s.log.Debug().Str("account", name).Msg("Received unwanted account from server; ignoring")
				return
			}

			// Ensure we can unlock the account with a known passphrase.
			unlocked := false
			if unlocker, isUnlocker := account.(e2wtypes.AccountLocker); isUnlocker {
				for _, passphrase := range s.passphrases {
					if err := unlocker.Unlock(ctx, passphrase); err == nil {
						unlocked = true
						break
					}
				}
			}
			if !unlocked {
				s.log.Warn().Str("account", name).Msg("Failed to unlock account with any passphrase")
				return
			}
			s.log.Trace().Str("account", name).Msg("Obtained and unlocked account")

			// Set up account as unknown to beacon chain.
			mu.Lock()
			accounts[util.ValidatorPubkey(account)] = account
			mu.Unlock()
		}(ctx, sem, &wg, wallet, account, accounts, &mu)
	}
	wg.Wait()
}

// AccountByPublicKey returns the account for the given public key.
func (s *Service) AccountByPublicKey(_ context.Context, pubkey phase0.BLSPubKey) (e2wtypes.Account, error) {
	s.mutex.RLock()
	account, exists := s.accounts[pubkey]
	s.mutex.RUnlock()
	if !exists {
		return nil, errors.New("not found")
	}
	return account, nil
}

// HasSlashingProtection returns true if the account manage provides built-in slashing protection.
func (*Service) HasSlashingProtection() bool {
	return true
}
