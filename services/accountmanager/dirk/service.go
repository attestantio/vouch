// Copyright © 2020 - 2024 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/credentials"
)

// Service is the manager for dirk accounts.
type Service struct {
	mutex                sync.RWMutex
	monitor              metrics.AccountManagerMonitor
	clientMonitor        metrics.ClientMonitor
	timeout              time.Duration
	processConcurrency   int64
	endpoints            []*dirk.Endpoint
	accountPaths         []string
	credentials          credentials.TransportCredentials
	accounts             map[phase0.BLSPubKey]e2wtypes.Account
	pubKeys              []phase0.BLSPubKey
	validatorsManager    validatorsmanager.Service
	domainProvider       eth2client.DomainProvider
	farFutureEpoch       phase0.Epoch
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
	log.Trace().Int("endpoints", len(endpoints)).Msg("Configured endpoints")

	farFutureEpoch, err := parameters.farFutureEpochProvider.FarFutureEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain far future epoch")
	}

	s := &Service{
		monitor:              parameters.monitor,
		clientMonitor:        parameters.clientMonitor,
		timeout:              parameters.timeout,
		processConcurrency:   parameters.processConcurrency,
		endpoints:            endpoints,
		accountPaths:         parameters.accountPaths,
		credentials:          credentials,
		domainProvider:       parameters.domainProvider,
		validatorsManager:    parameters.validatorsManager,
		farFutureEpoch:       farFutureEpoch,
		currentEpochProvider: parameters.currentEpochProvider,
		wallets:              make(map[string]e2wtypes.Wallet),
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	s.refreshAccounts(ctx)
	if err := s.refreshValidators(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to fetch initial validator states")
	}

	return s, nil
}

// Refresh refreshes the accounts from Dirk, and account validator state from
// the validators provider.
// This is a relatively expensive operation, so should not be run in the validating path.
func (s *Service) Refresh(ctx context.Context) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "Refresh")
	defer span.End()

	s.refreshAccounts(ctx)

	s.mutex.RLock()
	numAccounts := len(s.accounts)
	s.mutex.RUnlock()

	if numAccounts > 0 {
		if err := s.refreshValidators(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to refresh validators")
		}
	}
}

// refreshAccounts refreshes the accounts from Dirk.
func (s *Service) refreshAccounts(ctx context.Context) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "refreshAccounts")
	defer span.End()

	// Create the relevant wallets.
	pathsByWallet := make(map[string][]string)
	for _, path := range s.accountPaths {
		pathBits := strings.Split(path, "/")

		if _, exists := pathsByWallet[pathBits[0]]; !exists {
			pathsByWallet[pathBits[0]] = make([]string, 0)
		}
		pathsByWallet[pathBits[0]] = append(pathsByWallet[pathBits[0]], path)
	}

	verificationRegexes := accountPathsToVerificationRegexes(s.accountPaths)

	// Fetch accounts for each wallet in parallel.
	log.Trace().Int("wallets", len(pathsByWallet)).Msg("Fetching accounts for wallets")
	started := time.Now()
	accounts := make(map[phase0.BLSPubKey]e2wtypes.Account)
	var accountsMu sync.Mutex
	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	pubKeys := make([]phase0.BLSPubKey, 0)
	for walletName := range pathsByWallet {
		wg.Add(1)
		go func(ctx context.Context, sem *semaphore.Weighted, wg *sync.WaitGroup, walletName string, mu *sync.Mutex) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)
			wallet, err := s.openWallet(ctx, walletName)
			if err != nil {
				log.Warn().Err(err).Str("wallet", walletName).Msg("Failed to open wallet")
				return
			}
			log := log.With().Str("wallet", wallet.Name()).Logger()
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained semaphore")
			walletAccounts := s.fetchAccountsForWallet(ctx, wallet, verificationRegexes[wallet.Name()])
			log.Trace().Dur("elapsed", time.Since(started)).Int("accounts", len(walletAccounts)).Msg("Obtained accounts")
			mu.Lock()
			for k, v := range walletAccounts {
				accounts[k] = v
				pubKeys = append(pubKeys, k)
			}
			mu.Unlock()
			log.Trace().Dur("elapsed", time.Since(started)).Int("accounts", len(walletAccounts)).Msg("Imported accounts")
		}(ctx, sem, &wg, walletName, &accountsMu)
	}
	wg.Wait()
	log.Trace().Int("accounts", len(accounts)).Msg("Obtained accounts")

	s.mutex.Lock()
	if len(accounts) == 0 && len(s.accounts) != 0 {
		s.mutex.Unlock()
		log.Warn().Msg("No accounts obtained; retaining old list")
		return
	}
	s.accounts = accounts
	s.pubKeys = pubKeys
	s.mutex.Unlock()
}

// openWallet opens a wallet, using an existing one if present.
func (s *Service) openWallet(ctx context.Context, name string) (e2wtypes.Wallet, error) {
	s.walletsMutex.Lock()
	defer s.walletsMutex.Unlock()

	wallet, exists := s.wallets[name]
	var err error
	if !exists {
		wallet, err = dirk.Open(ctx,
			dirk.WithMonitor(s.monitor.(metrics.Service)),
			dirk.WithName(name),
			dirk.WithCredentials(s.credentials),
			dirk.WithEndpoints(s.endpoints),
			dirk.WithTimeout(s.timeout),
		)
		// wallet, err = dirk.OpenWallet(ctx, name, s.credentials, s.endpoints)
		if err != nil {
			return nil, err
		}
		s.wallets[name] = wallet
	}

	return wallet, nil
}

// refreshValidators refreshes the validator information for our known accounts.
func (s *Service) refreshValidators(ctx context.Context) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "refreshValidators")
	defer span.End()

	s.mutex.RLock()
	pubKeys := s.pubKeys
	s.mutex.RUnlock()
	log.Trace().Int("accounts", len(pubKeys)).Msg("Refreshing validators of accounts")

	if err := s.validatorsManager.RefreshValidatorsFromBeaconNode(ctx, pubKeys); err != nil {
		return errors.Wrap(err, "failed to refresh validators")
	}
	return nil
}

func credentialsFromCerts(ctx context.Context, clientCert []byte, clientKey []byte, caCert []byte) (credentials.TransportCredentials, error) {
	_, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "credentialsFromCerts")
	defer span.End()

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
func (s *Service) ValidatingAccountsForEpoch(ctx context.Context, epoch phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "ValidatingAccountsForEpoch", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

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

	s.mutex.RLock()
	pubKeys := s.pubKeys
	s.mutex.RUnlock()

	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	validatingAccounts := make(map[phase0.ValidatorIndex]e2wtypes.Account, len(validators))
	s.mutex.RLock()
	for index, validator := range validators {
		state := api.ValidatorToState(validator, nil, epoch, s.farFutureEpoch)
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
	s.mutex.RUnlock()

	// Update metrics if this is the current epoch.
	if epoch == s.currentEpochProvider.CurrentEpoch() {
		stateCount[api.ValidatorStateUnknown] += uint64(len(pubKeys) - len(validators))
		for state, count := range stateCount {
			s.monitor.Accounts(strings.ToLower(state.String()), count)
		}
	}

	return validatingAccounts, nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *Service) ValidatingAccountsForEpochByIndex(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "ValidatingAccountsForEpochByIndex", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

	s.mutex.RLock()
	pubKeys := s.pubKeys
	s.mutex.RUnlock()

	indexPresenceMap := make(map[phase0.ValidatorIndex]bool)
	for _, index := range indices {
		indexPresenceMap[index] = true
	}
	validators := s.validatorsManager.ValidatorsByPubKey(ctx, pubKeys)
	validatingAccounts := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	for index, validator := range validators {
		if _, present := indexPresenceMap[index]; !present {
			continue
		}
		state := api.ValidatorToState(validator, nil, epoch, s.farFutureEpoch)
		if state == api.ValidatorStateActiveOngoing || state == api.ValidatorStateActiveExiting {
			s.mutex.RLock()
			validatingAccounts[index] = s.accounts[validator.PublicKey]
			s.mutex.RUnlock()
		}
	}

	return validatingAccounts, nil
}

// accountPathsToVerificationRegexes turns account paths in to regexes to allow verification.
func accountPathsToVerificationRegexes(paths []string) map[string][]*regexp.Regexp {
	regexes := make(map[string][]*regexp.Regexp, len(paths))
	for _, path := range paths {
		log := log.With().Str("path", path).Logger()
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			log.Debug().Msg("Invalid path")
			continue
		}
		if len(parts) == 1 {
			parts = append(parts, ".*")
		}
		if parts[1] == "" {
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
		if _, exists := regexes[parts[0]]; !exists {
			regexes[parts[0]] = make([]*regexp.Regexp, 0)
		}
		regexes[parts[0]] = append(regexes[parts[0]], regex)
	}
	return regexes
}

func (*Service) fetchAccountsForWallet(ctx context.Context, wallet e2wtypes.Wallet, verificationRegexes []*regexp.Regexp) map[phase0.BLSPubKey]e2wtypes.Account {
	ctx, span := otel.Tracer("attestantio.vouch.services.accountmanager.dirk").Start(ctx, "fetchAccountsForWallet", trace.WithAttributes(
		attribute.String("wallet", wallet.Name()),
	))
	defer span.End()

	res := make(map[phase0.BLSPubKey]e2wtypes.Account)
	accounts := wallet.Accounts(ctx)

	// Short circuit these checks if the verification regex is 'everything'.
	shortCircuitRegex := fmt.Sprintf("^%s/.*$", wallet.Name())
	shortCircuit := false
	if len(verificationRegexes) == 1 && verificationRegexes[0].String() == shortCircuitRegex {
		log.Trace().Str("wallet", wallet.Name()).Msg("Short-circuiting regex checks")
		shortCircuit = true
	}

	for account := range accounts {
		if !shortCircuit {
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
				log.Debug().Str("account", name).Msg("Received unwanted account from server; ignoring")
				continue
			}
		}

		res[util.ValidatorPubkey(account)] = account
	}

	return res
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
