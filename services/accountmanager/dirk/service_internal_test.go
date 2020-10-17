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
	"fmt"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/attestantio/dirk/testing/daemon"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testing/resources"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestFetchAccountsForWallet(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, e2types.InitBLS())

	wallets := setupTestWallets(ctx, t,
		[]*walletDef{
			{
				name: "wallet1",
				seed: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				},
				accountNames: []string{"account1", "account2", "account3"},
			},
		})

	// Test with wallet regex.
	s, err := setupService(ctx, t, []string{"localhost:12345"}, []string{"wallet1", "wallet2"})
	require.NoError(t, err)
	validatingAccounts := make(map[[48]byte]*ValidatingAccount)
	for account := range wallets[0].Accounts(ctx) {
		var key [48]byte
		copy(key[:], account.PublicKey().Marshal())
		validatingAccounts[key] = &ValidatingAccount{
			account: account,
		}
	}
	verificationRegexes := make([]*regexp.Regexp, 0)
	verificationRegexes = append(verificationRegexes, regexp.MustCompile("wallet1"))
	s.fetchAccountsForWallet(ctx, wallets[0], validatingAccounts, verificationRegexes)
	for _, validatingAccount := range validatingAccounts {
		require.NotNil(t, validatingAccount.accountManager)
	}

	// Test with single account regex.
	capture := logger.NewLogCapture()
	s, err = setupService(ctx, t, []string{"localhost:12345"}, []string{"wallet1", "wallet2"})
	require.NoError(t, err)
	validatingAccounts = make(map[[48]byte]*ValidatingAccount)
	for account := range wallets[0].Accounts(ctx) {
		var key [48]byte
		copy(key[:], account.PublicKey().Marshal())
		validatingAccounts[key] = &ValidatingAccount{
			account: account,
		}
	}
	verificationRegexes = make([]*regexp.Regexp, 0)
	verificationRegexes = append(verificationRegexes, regexp.MustCompile("1$"))
	s.fetchAccountsForWallet(ctx, wallets[0], validatingAccounts, verificationRegexes)
	fetched := 0
	for _, validatingAccount := range validatingAccounts {
		if validatingAccount.accountManager != nil {
			fetched++
		}
	}
	require.Equal(t, 1, fetched)
	capture.AssertHasEntry(t, "Received unwanted account from server; ignoring")
}

func TestAccountPathsToVerificationRegexes(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		regexes  []*regexp.Regexp
		logEntry string
	}{
		{
			name: "Empty",
		},
		{
			name:     "InvalidPath",
			paths:    []string{"/account1"},
			logEntry: "Invalid path",
		},
		{
			name:    "Wallet",
			paths:   []string{"wallet1"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/.*$")},
		},
		{
			name:    "WalletTrailing",
			paths:   []string{"wallet1/"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/.*$")},
		},
		{
			name:    "Account",
			paths:   []string{"wallet1/acc"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/acc$")},
		},
		{
			name:    "WalletRegex",
			paths:   []string{"wallet[0123]/a.*b[abc]{1}"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet[0123]/a.*b[abc]{1}$")},
		},
		{
			name:    "AccountRegex",
			paths:   []string{"wallet1/a.*b[abc]{1}"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/a.*b[abc]{1}$")},
		},
		{
			name:    "AccountRegexEndAnchor",
			paths:   []string{"wallet1/a.*b[abc]{1}$"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/a.*b[abc]{1}$")},
		},
		{
			name:    "AccountRegexStartAnchor",
			paths:   []string{"^wallet1/a.*b[abc]{1}"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/a.*b[abc]{1}$")},
		},
		{
			name:    "AccountRegexFullAnchor",
			paths:   []string{"^wallet1/a.*b[abc]{1}$"},
			regexes: []*regexp.Regexp{regexp.MustCompile("^wallet1/a.*b[abc]{1}$")},
		},
		{
			name:     "InvalidRegex",
			paths:    []string{"wallet1/a.***"},
			logEntry: "Invalid path regex",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			// Need to set up the service to set the module-wide logging.
			_, err := setupService(context.Background(), t, []string{"localhost:123456"}, []string{"wallet1"})
			require.NoError(t, err)
			regexes := accountPathsToVerificationRegexes(test.paths)
			require.Equal(t, len(test.regexes), len(regexes))
			for i := range test.regexes {
				require.Equal(t, test.regexes[i], regexes[i])
			}
			if test.logEntry != "" {
				capture.AssertHasEntry(t, test.logEntry)
			}
		})
	}
}

func TestAccounts(t *testing.T) {
	tests := []struct {
		name     string
		accounts map[[48]byte]*ValidatingAccount
		expected int
	}{
		{
			name: "Empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := setupService(context.Background(), t, []string{"localhost:123456"}, []string{"wallet1"})
			require.NoError(t, err)
			// Manually add accounts.
			s.accounts = test.accounts
			accounts, err := s.Accounts(context.Background())
			require.NoError(t, err)
			require.Equal(t, test.expected, len(accounts))
		})
	}
}

func TestUpdateAccountsState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.NoError(t, err)

	s, err := setupService(context.Background(), t, []string{fmt.Sprintf("signer-test01:%d", port)}, []string{"Wallet 1", "Wallet 2"})
	require.NoError(t, err)
	accounts, err := s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 16, len(accounts))

	// Manually clear out the accounts state.
	for _, account := range s.accounts {
		account.state = api.ValidatorStateUnknown
	}

	// Confirm that validators are unknown (hence not returned).
	accounts, err = s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(accounts))

	// Update and re-check.
	require.NoError(t, s.UpdateAccountsState(ctx))
	accounts, err = s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 16, len(accounts))
}

func TestUpdateAccountsStateWithoutBalances(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.NoError(t, err)

	s, err := New(ctx,
		WithLogLevel(zerolog.TraceLevel),
		WithMonitor(nullmetrics.New(context.Background())),
		WithClientMonitor(nullmetrics.New(context.Background())),
		WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
		WithAccountPaths([]string{"Wallet 1", "Wallet 2"}),
		WithClientCert([]byte(resources.ClientTest01Crt)),
		WithClientKey([]byte(resources.ClientTest01Key)),
		WithCACert([]byte(resources.CACrt)),
		WithValidatorsProvider(mock.NewValidatorsWithoutBalanceProvider()),
		WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
	require.NoError(t, err)
	accounts, err := s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 16, len(accounts))

	// Manually clear out the accounts state.
	for _, account := range s.accounts {
		account.state = api.ValidatorStateUnknown
	}

	// Confirm that validators are unknown (hence not returned).
	accounts, err = s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(accounts))

	// Update and re-check.
	require.NoError(t, s.UpdateAccountsState(ctx))
	accounts, err = s.Accounts(ctx)
	require.NoError(t, err)
	require.Equal(t, 16, len(accounts))
}

func setupService(ctx context.Context, t *testing.T, endpoints []string, accountPaths []string) (*Service, error) {
	return New(ctx,
		WithLogLevel(zerolog.TraceLevel),
		WithMonitor(nullmetrics.New(context.Background())),
		WithClientMonitor(nullmetrics.New(context.Background())),
		WithEndpoints(endpoints),
		WithAccountPaths(accountPaths),
		WithClientCert([]byte(resources.ClientTest01Crt)),
		WithClientKey([]byte(resources.ClientTest01Key)),
		WithCACert([]byte(resources.CACrt)),
		WithValidatorsProvider(mock.NewValidatorsProvider()),
		WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
		WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
		WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
		WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
		WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
		WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
		WithSignatureDomainProvider(mock.NewSignatureDomainProvider()),
	)
}

// walletDef defines a wallet to be created.
type walletDef struct {
	name         string
	seed         []byte
	accountNames []string
}

// setupTestWallet creates wallets given definitions.
func setupTestWallets(ctx context.Context, t *testing.T, defs []*walletDef) []e2wtypes.Wallet {
	store := scratch.New()
	encryptor := keystorev4.New()

	wallets := make([]e2wtypes.Wallet, 0, len(defs))
	for _, def := range defs {
		wallet, err := hd.CreateWallet(ctx, def.name, []byte("pass"), store, encryptor, def.seed)
		require.NoError(t, err)
		require.Nil(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
		for _, accountName := range def.accountNames {
			_, err = wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), accountName, []byte("pass"))
			require.NoError(t, err)
		}
		wallets = append(wallets, wallet)
	}

	return wallets
}
