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

package dirk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-bytesutil"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc/credentials"
)

// Service is the manager for dirk accounts.
type Service struct {
	mutex                sync.RWMutex
	monitor              metrics.AccountManagerMonitor
	clientMonitor        metrics.ClientMonitor
	endpoints            []*dirk.Endpoint
	accountPaths         []string
	credentials          credentials.TransportCredentials
	accounts             map[spec.BLSPubKey]e2wtypes.Account
	validatorsManager    validatorsmanager.Service
	domainProvider       eth2client.DomainProvider
	farFutureEpoch       spec.Epoch
	currentEpochProvider chaintime.Service
	wallets              map[string]e2wtypes.Wallet
	walletsMutex         sync.RWMutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new dirk account manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "accountmanager").Str("impl", "dirk").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	credentials, err := credentialsFromCerts(ctx, parameters.clientCert, parameters.clientKey, parameters.caCert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build credentials")
	}

	endpoints := make([]*dirk.Endpoint, 0, len(parameters.endpoints))
	for _, endpoint := range parameters.endpoints {
		endpointParts := strings.Split(endpoint, ":")
		if len(endpointParts) != 2 {
			log.Warn().Str("endpoint", endpoint).Msg("Malformed endpoint")
			continue
		}
		port, err := strconv.ParseUint(endpointParts[1], 10, 32)
		if err != nil {
			log.Warn().Str("endpoint", endpoint).Err(err).Msg("Malformed port")
			continue
		}
		if port == 0 {
			log.Warn().Str("endpoint", endpoint).Msg("Invalid port")
			continue
		}
		endpoints = append(endpoints, dirk.NewEndpoint(endpointParts[0], uint32(port)))
	}
	if len(endpoints) == 0 {
		return nil, errors.New("no valid endpoints specified")
	}

	farFutureEpoch, err := parameters.farFutureEpochProvider.FarFutureEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain far future epoch")
	}

	s := &Service{
		monitor:              parameters.monitor,
		clientMonitor:        parameters.clientMonitor,
		endpoints:            endpoints,
		accountPaths:         parameters.accountPaths,
		credentials:          credentials,
		domainProvider:       parameters.domainProvider,
		validatorsManager:    parameters.validatorsManager,
		farFutureEpoch:       farFutureEpoch,
		currentEpochProvider: parameters.currentEpochProvider,
		wallets:              make(map[string]e2wtypes.Wallet),
	}

	if err := s.refreshAccounts(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch initial accounts")
	}
	if err := s.refreshValidators(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch initial validator states")
	}

	return s, nil
}

// Refresh refreshes the accounts from Dirk, and account validator state from
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

// refreshAccounts refreshes the accounts from Dirk.
func (s *Service) refreshAccounts(ctx context.Context) error {
	// Create the relevant wallets.
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
		wallet, err := s.openWallet(ctx, pathBits[0])
		if err != nil {
			log.Warn().Err(err).Str("wallet", pathBits[0]).Msg("Failed to open wallet")
		} else {
			wallets[wallet.Name()] = wallet
		}
	}

	verificationRegexes := accountPathsToVerificationRegexes(s.accountPaths)
	// Fetch accounts for each wallet.
	accounts := make(map[spec.BLSPubKey]e2wtypes.Account)
	for _, wallet := range wallets {
		// if _, isProvider := wallet.(e2wtypes.WalletAccountsByPathProvider); isProvider {
		// 	fmt.Printf("TODO: fetch accounts by path")
		// } else {
		walletAccounts := s.fetchAccountsForWallet(ctx, wallet, verificationRegexes)
		for k, v := range walletAccounts {
			accounts[k] = v
		}
		//}
	}
	log.Trace().Int("accounts", len(accounts)).Msg("Obtained accounts")

	if len(accounts) == 0 && len(s.accounts) != 0 {
		log.Warn().Msg("No accounts obtained; retaining old list")
		return nil
	}

	s.mutex.Lock()
	s.accounts = accounts
	s.mutex.Unlock()

	return nil
}

// openWallet opens a wallet, using an existing one if present.
func (s *Service) openWallet(ctx context.Context, name string) (e2wtypes.Wallet, error) {
	s.walletsMutex.Lock()
	defer s.walletsMutex.Unlock()

	wallet, exists := s.wallets[name]
	var err error
	if !exists {
		wallet, err = dirk.OpenWallet(ctx, name, s.credentials, s.endpoints)
		if err != nil {
			return nil, err
		}
		s.wallets[name] = wallet
	}

	return wallet, nil
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

func credentialsFromCerts(ctx context.Context, clientCert []byte, clientKey []byte, caCert []byte) (credentials.TransportCredentials, error) {
	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client keypair")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		MinVersion:   tls.VersionTLS13,
	}

	if caCert != nil {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to add CA certificate")
		}
		tlsCfg.RootCAs = cp
	}

	return credentials.NewTLS(tlsCfg), nil
}

// ValidatingAccountsForEpoch obtains the validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpoch(ctx context.Context, epoch spec.Epoch) (map[spec.ValidatorIndex]e2wtypes.Account, error) {
	// stateCount is used to update metrics.
	stateCount := map[api.ValidatorState]uint64{
		api.ValidatorStateUnknown:            0,
		api.ValidatorStatePendingInitialized: 0,
		api.ValidatorStatePendingQueued:      0,
		api.ValidatorStateActiveOngoing:      0,
		api.ValidatorStateActiveExiting:      0,
		api.ValidatorStateActiveSlashed:      0,
		api.ValidatorStateExitedUnslashed:    0,
		api.ValidatorStateExitedSlashed:      0,
		api.ValidatorStateWithdrawalPossible: 0,
		api.ValidatorStateWithdrawalDone:     0,
	}

	validatingAccounts := make(map[spec.ValidatorIndex]e2wtypes.Account)
	pubKeys := make([]spec.BLSPubKey, 0, len(s.accounts))
	for pubKey := range s.accounts {
		pubKeys = append(pubKeys, pubKey)
	}

	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	for index, validator := range validators {
		state := api.ValidatorToState(validator, epoch, s.farFutureEpoch)
		stateCount[state]++
		if state == api.ValidatorStateActiveOngoing || state == api.ValidatorStateActiveExiting {
			account := s.accounts[validator.PublicKey]
			log.Trace().
				Str("name", account.Name()).
				Str("public_key", fmt.Sprintf("%x", account.PublicKey().Marshal())).
				Uint64("index", uint64(index)).
				Str("state", state.String()).
				Msg("Validating account")
			validatingAccounts[index] = account
		}
	}

	// Update metrics if this is the current epoch.
	if epoch == s.currentEpochProvider.CurrentEpoch() {
		stateCount[api.ValidatorStateUnknown] += uint64(len(s.accounts) - len(validators))
		for state, count := range stateCount {
			s.monitor.Accounts(strings.ToLower(state.String()), count)
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
		if len(parts[1]) == 0 {
			parts[1] = ".*"
		}
		parts[0] = strings.TrimPrefix(parts[0], "^")
		parts[0] = strings.TrimSuffix(parts[0], "$")
		parts[1] = strings.TrimPrefix(parts[1], "^")
		parts[1] = strings.TrimSuffix(parts[1], "$")
		specifier := fmt.Sprintf("^%s/%s$", parts[0], parts[1])
		regex, err := regexp.Compile(specifier)
		if err != nil {
			log.Warn().Str("specifier", specifier).Err(err).Msg("Invalid path regex")
			continue
		}
		regexes = append(regexes, regex)
	}
	return regexes
}

func (s *Service) fetchAccountsForWallet(ctx context.Context, wallet e2wtypes.Wallet, verificationRegexes []*regexp.Regexp) map[spec.BLSPubKey]e2wtypes.Account {
	res := make(map[spec.BLSPubKey]e2wtypes.Account)
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

		res[bytesutil.ToBytes48(pubKey)] = account
	}
	return res
}
