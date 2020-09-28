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

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/loggers"
	"github.com/attestantio/vouch/services/accountmanager"
	dirkaccountmanager "github.com/attestantio/vouch/services/accountmanager/dirk"
	walletaccountmanager "github.com/attestantio/vouch/services/accountmanager/wallet"
	standardattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/standard"
	standardattester "github.com/attestantio/vouch/services/attester/standard"
	standardbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/standard"
	standardbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	standardcontroller "github.com/attestantio/vouch/services/controller/standard"
	"github.com/attestantio/vouch/services/graffitiprovider"
	dynamicgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/dynamic"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	basicscheduler "github.com/attestantio/vouch/services/scheduler/basic"
	"github.com/attestantio/vouch/services/submitter"
	immediatesubmitter "github.com/attestantio/vouch/services/submitter/immediate"
	multinodesubmitter "github.com/attestantio/vouch/services/submitter/multinode"
	bestbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	firstbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	"github.com/aws/aws-sdk-go/aws/credentials"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	jaegerconfig "github.com/uber/jaeger-client-go/config"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	majordomo "github.com/wealdtech/go-majordomo"
	asmconfidant "github.com/wealdtech/go-majordomo/confidants/asm"
	directconfidant "github.com/wealdtech/go-majordomo/confidants/direct"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	gsmconfidant "github.com/wealdtech/go-majordomo/confidants/gsm"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	if err := fetchConfig(); err != nil {
		zerologger.Fatal().Err(err).Msg("Failed to fetch configuration")
	}

	if err := initLogging(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise logging")
	}

	majordomo, err := initMajordomo(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise majordomo")
	}

	logModules()
	log.Info().Str("version", "v0.6.0").Msg("Starting vouch")

	if err := initProfiling(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise profiling")
	}

	closer, err := initTracing()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise tracing")
	}
	if closer != nil {
		defer closer.Close()
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 8)

	if err := e2types.InitBLS(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise BLS library")
	}

	if err := startServices(ctx, majordomo); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise services")
	}

	log.Info().Msg("All services operational")

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	for {
		sig := <-sigCh
		if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == os.Interrupt || sig == os.Kill {
			cancel()
			break
		}
	}

	log.Info().Msg("Stopping vouch")
}

// fetchConfig fetches configuration from various sources.
func fetchConfig() error {
	pflag.String("base-dir", "", "base directory for configuration files")
	pflag.String("log-level", "info", "minimum level of messsages to log")
	pflag.String("log-file", "", "redirect log output to a file")
	pflag.String("profile-address", "", "Address on which to run Go profile server")
	pflag.String("tracing-address", "", "Address to which to send tracing data")
	pflag.String("beacon-node-address", "localhost:4000", "Address on which to contact the beacon node")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		return errors.Wrap(err, "failed to bind pflags to viper")
	}

	if viper.GetString("base-dir") != "" {
		// User-defined base directory.
		viper.AddConfigPath(resolvePath(""))
		viper.SetConfigName("vouch")
	} else {
		// Home directory.
		home, err := homedir.Dir()
		if err != nil {
			return errors.Wrap(err, "failed to obtain home directory")
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".vouch")
	}

	// Environment settings.
	viper.SetEnvPrefix("VOUCH")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// Defaults.
	viper.Set("process-concurrency", 16)
	viper.Set("eth2client.timeout", 2*time.Minute)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return errors.Wrap(err, "failed to read configuration file")
		}
	}

	return nil
}

// initTracing initialises the tracing system.
func initTracing() (io.Closer, error) {
	tracingAddress := viper.GetString("tracing-address")
	if tracingAddress == "" {
		return nil, nil
	}
	cfg := &jaegerconfig.Configuration{
		ServiceName: "vouch",
		Sampler: &jaegerconfig.SamplerConfig{
			Type:  "probabilistic",
			Param: 0.1,
		},
		Reporter: &jaegerconfig.ReporterConfig{
			LogSpans:           true,
			LocalAgentHostPort: tracingAddress,
		},
	}
	tracer, closer, err := cfg.NewTracer(jaegerconfig.Logger(loggers.NewJaegerLogger(log)))
	if err != nil {
		return nil, err
	}
	if tracer != nil {
		opentracing.SetGlobalTracer(tracer)
	}
	return closer, nil
}

// initProfiling initialises the profiling server.
func initProfiling() error {
	profileAddress := viper.GetString("profile-address")
	if profileAddress != "" {
		go func() {
			log.Info().Str("profile_address", profileAddress).Msg("Starting profile server")
			runtime.SetMutexProfileFraction(1)
			if err := http.ListenAndServe(profileAddress, nil); err != nil {
				log.Warn().Str("profile_address", profileAddress).Err(err).Msg("Failed to run profile server")
			}
		}()
	}
	return nil
}

func startServices(ctx context.Context, majordomo majordomo.Service) error {
	log.Trace().Msg("Starting metrics service")
	monitor, err := startMonitor(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to start metrics service")
	}

	log.Trace().Msg("Starting Ethereum 2 client service")
	eth2Client, err := fetchClient(ctx, viper.GetString("beacon-node-address"))
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to fetch client %q", viper.GetString("beacon-node-address")))
	}

	log.Trace().Msg("Starting chain time service")
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(logLevel(viper.GetString("chaintime.log-level"))),
		standardchaintime.WithGenesisTimeProvider(eth2Client.(eth2client.GenesisTimeProvider)),
		standardchaintime.WithSlotDurationProvider(eth2Client.(eth2client.SlotDurationProvider)),
		standardchaintime.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start chain time service")
	}

	log.Trace().Msg("Starting scheduler")
	scheduler, err := basicscheduler.New(ctx,
		basicscheduler.WithLogLevel(logLevel(viper.GetString("scheduler.log-level"))),
		basicscheduler.WithMonitor(monitor.(metrics.SchedulerMonitor)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start scheduler service")
	}

	log.Trace().Msg("Starting account manager")
	accountManager, err := startAccountManager(ctx, monitor, eth2Client, majordomo)
	if err != nil {
		return errors.Wrap(err, "failed to start account manager")
	}

	log.Trace().Msg("Selecting submitter strategy")
	submitterStrategy, err := selectSubmitterStrategy(ctx, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to select submitter")
	}

	log.Trace().Msg("Starting graffiti provider")
	graffitiProvider, err := startGraffitiProvider(ctx, monitor, majordomo)
	if err != nil {
		return errors.Wrap(err, "failed to start graffiti provider")
	}

	log.Trace().Msg("Selecting beacon block proposal provider")
	beaconBlockProposalProvider, err := selectBeaconBlockProposalProvider(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to select beacon block proposal provider")
	}

	log.Trace().Msg("Starting beacon block proposer")
	beaconBlockProposer, err := standardbeaconblockproposer.New(ctx,
		standardbeaconblockproposer.WithLogLevel(logLevel(viper.GetString("beaconblockproposer.log-level"))),
		standardbeaconblockproposer.WithProposalDataProvider(beaconBlockProposalProvider),
		standardbeaconblockproposer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardbeaconblockproposer.WithGraffitiProvider(graffitiProvider),
		standardbeaconblockproposer.WithMonitor(monitor.(metrics.BeaconBlockProposalMonitor)),
		standardbeaconblockproposer.WithBeaconBlockSubmitter(submitterStrategy.(submitter.BeaconBlockSubmitter)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon block proposer service")
	}

	log.Trace().Msg("Starting beacon block attester")
	attester, err := standardattester.New(ctx,
		standardattester.WithLogLevel(logLevel(viper.GetString("attester.log-level"))),
		standardattester.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
		standardattester.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
		standardattester.WithAttestationDataProvider(eth2Client.(eth2client.AttestationDataProvider)),
		standardattester.WithAttestationSubmitter(submitterStrategy.(submitter.AttestationSubmitter)),
		standardattester.WithMonitor(monitor.(metrics.AttestationMonitor)),
		standardattester.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon block attester service")
	}

	log.Trace().Msg("Starting beacon attestation aggregator")
	attestationAggregator, err := standardattestationaggregator.New(ctx,
		standardattestationaggregator.WithLogLevel(logLevel(viper.GetString("attestationaggregator.log-level"))),
		standardattestationaggregator.WithTargetAggregatorsPerCommitteeProvider(eth2Client.(eth2client.TargetAggregatorsPerCommitteeProvider)),
		standardattestationaggregator.WithAggregateAttestationDataProvider(eth2Client.(eth2client.NonSpecAggregateAttestationProvider)),
		standardattestationaggregator.WithAggregateAttestationSubmitter(submitterStrategy.(submitter.AggregateAttestationSubmitter)),
		standardattestationaggregator.WithMonitor(monitor.(metrics.AttestationAggregationMonitor)),
		standardattestationaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon attestation aggregator service")
	}

	log.Trace().Msg("Starting beacon committee subscriber service")
	beaconCommitteeSubscriber, err := standardbeaconcommitteesubscriber.New(ctx,
		standardbeaconcommitteesubscriber.WithLogLevel(logLevel(viper.GetString("beaconcommiteesubscriber.log-level"))),
		standardbeaconcommitteesubscriber.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
		standardbeaconcommitteesubscriber.WithMonitor(monitor.(metrics.BeaconCommitteeSubscriptionMonitor)),
		standardbeaconcommitteesubscriber.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardbeaconcommitteesubscriber.WithAttestationAggregator(attestationAggregator),
		standardbeaconcommitteesubscriber.WithBeaconCommitteeSubmitter(submitterStrategy.(submitter.BeaconCommitteeSubscriptionsSubmitter)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon committee subscriber service")
	}

	log.Trace().Msg("Starting controller")
	_, err = standardcontroller.New(ctx,
		standardcontroller.WithLogLevel(logLevel(viper.GetString("controller.log-level"))),
		standardcontroller.WithMonitor(monitor.(metrics.ControllerMonitor)),
		standardcontroller.WithSlotDurationProvider(eth2Client.(eth2client.SlotDurationProvider)),
		standardcontroller.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
		standardcontroller.WithChainTimeService(chainTime),
		standardcontroller.WithProposerDutiesProvider(eth2Client.(eth2client.ProposerDutiesProvider)),
		standardcontroller.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardcontroller.WithBeaconChainHeadUpdatedSource(eth2Client.(eth2client.BeaconChainHeadUpdatedSource)),
		standardcontroller.WithScheduler(scheduler),
		standardcontroller.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardcontroller.WithAttester(attester),
		standardcontroller.WithBeaconBlockProposer(beaconBlockProposer),
		standardcontroller.WithAttestationAggregator(attestationAggregator),
		standardcontroller.WithBeaconCommitteeSubscriber(beaconCommitteeSubscriber),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start controller service")
	}

	return nil
}

func logModules() {
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		log.Trace().Str("path", buildInfo.Path).Msg("Main package")
		for _, dep := range buildInfo.Deps {
			log := log.Trace()
			if dep.Replace == nil {
				log = log.Str("path", dep.Path).Str("version", dep.Version)
			} else {
				log = log.Str("path", dep.Replace.Path).Str("version", dep.Replace.Version)
			}
			log.Msg("Dependency")
		}
	}
}

// resolvePath resolves a potentially relative path to an absolute path.
func resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	baseDir := viper.GetString("base-dir")
	if baseDir == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not determine a home directory")
		}
		baseDir = homeDir
	}
	return filepath.Join(baseDir, path)
}

func initMajordomo(ctx context.Context) (majordomo.Service, error) {
	majordomo, err := standardmajordomo.New(ctx,
		standardmajordomo.WithLogLevel(logLevel(viper.GetString("majordomo.log-level"))),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create majordomo service")
	}

	directConfidant, err := directconfidant.New(ctx,
		directconfidant.WithLogLevel(logLevel(viper.GetString("majordomo.confidants.direct.log-level"))),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create direct confidant")
	}
	if err := majordomo.RegisterConfidant(ctx, directConfidant); err != nil {
		return nil, errors.Wrap(err, "failed to register direct confidant")
	}

	fileConfidant, err := fileconfidant.New(ctx,
		fileconfidant.WithLogLevel(logLevel(viper.GetString("majordomo.confidants.file.log-level"))),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create file confidant")
	}
	if err := majordomo.RegisterConfidant(ctx, fileConfidant); err != nil {
		return nil, errors.Wrap(err, "failed to register file confidant")
	}

	if viper.GetString("majordomo.asm.region") != "" {
		var asmCredentials *credentials.Credentials
		if viper.GetString("majordomo.asm.id") != "" {
			asmCredentials = credentials.NewStaticCredentials(viper.GetString("majordomo.asm.id"), viper.GetString("majordomo.asm.secret"), "")
		}
		asmConfidant, err := asmconfidant.New(ctx,
			asmconfidant.WithLogLevel(logLevel(viper.GetString("majordomo.confidants.asm.log-level"))),
			asmconfidant.WithCredentials(asmCredentials),
			asmconfidant.WithRegion(viper.GetString("majordomo.asm.region")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create AWS secrets manager confidant")
		}
		if err := majordomo.RegisterConfidant(ctx, asmConfidant); err != nil {
			return nil, errors.Wrap(err, "failed to register AWS secrets manager confidant")
		}
	}

	if viper.GetString("majordomo.gsm.credentials") != "" {
		gsmConfidant, err := gsmconfidant.New(ctx,
			gsmconfidant.WithLogLevel(logLevel(viper.GetString("majordomo.confidants.gsm.log-level"))),
			gsmconfidant.WithCredentialsPath(resolvePath(viper.GetString("majordomo.gsm.credentials"))),
			gsmconfidant.WithProject(viper.GetString("majordomo.gsm.project")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create Google secret manager confidant")
		}
		if err := majordomo.RegisterConfidant(ctx, gsmConfidant); err != nil {
			return nil, errors.Wrap(err, "failed to register Google secret manager confidant")
		}
	}

	return majordomo, nil
}

func startMonitor(ctx context.Context) (metrics.Service, error) {
	log.Trace().Msg("Starting metrics service")
	var monitor metrics.Service
	if viper.Get("metrics.prometheus") != nil {
		var err error
		monitor, err = prometheusmetrics.New(ctx,
			prometheusmetrics.WithLogLevel(logLevel(viper.GetString("metrics.prometheus.log-level"))),
			prometheusmetrics.WithAddress(viper.GetString("metrics.prometheus.listen-address")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start prometheus metrics service")
		}
		log.Info().Str("listen_address", viper.GetString("metrics.prometheus.listen-address")).Msg("Started prometheus metrics service")
	} else {
		log.Debug().Msg("No metrics service supplied; monitor not starting")
		monitor = nullmetrics.New(ctx)
	}
	return monitor, nil
}

func startGraffitiProvider(ctx context.Context, monitor metrics.Service, majordomo majordomo.Service) (graffitiprovider.Service, error) {
	switch {
	case viper.Get("graffiti.dynamic") != nil:
		return dynamicgraffitiprovider.New(ctx,
			dynamicgraffitiprovider.WithMajordomo(majordomo),
			dynamicgraffitiprovider.WithLogLevel(logLevel(viper.GetString("graffiti.dynamic.log-level"))),
			dynamicgraffitiprovider.WithLocation(viper.GetString("graffiti.dynamic.location")),
		)
	default:
		return staticgraffitiprovider.New(ctx,
			staticgraffitiprovider.WithLogLevel(logLevel(viper.GetString("graffiti.static.log-level"))),
			staticgraffitiprovider.WithGraffiti([]byte(viper.GetString("graffiti.static.value"))),
		)
	}
}

func startAccountManager(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service, majordomo majordomo.Service) (accountmanager.Service, error) {
	var accountManager accountmanager.Service
	if viper.Get("accountmanager.dirk") != nil {
		certPEMBlock, err := majordomo.Fetch(ctx, viper.GetString("accountmanager.dirk.client-cert"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain server certificate")
		}
		keyPEMBlock, err := majordomo.Fetch(ctx, viper.GetString("accountmanager.dirk.client-key"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain server key")
		}
		var caPEMBlock []byte
		if viper.GetString("accountmanager.dirk.ca-cert") != "" {
			caPEMBlock, err = majordomo.Fetch(ctx, viper.GetString("accountmanager.dirk.ca-cert"))
			if err != nil {
				return nil, errors.Wrap(err, "failed to obtain client CA certificate")
			}
		}
		accountManager, err = dirkaccountmanager.New(ctx,
			dirkaccountmanager.WithLogLevel(logLevel(viper.GetString("accountmanager.dirk.log-level"))),
			dirkaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			dirkaccountmanager.WithValidatorsProvider(eth2Client.(eth2client.ValidatorsProvider)),
			dirkaccountmanager.WithEndpoints(viper.GetStringSlice("accountmanager.dirk.endpoints")),
			dirkaccountmanager.WithAccountPaths(viper.GetStringSlice("accountmanager.dirk.accounts")),
			dirkaccountmanager.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
			dirkaccountmanager.WithBeaconProposerDomainProvider(eth2Client.(eth2client.BeaconProposerDomainProvider)),
			dirkaccountmanager.WithBeaconAttesterDomainProvider(eth2Client.(eth2client.BeaconAttesterDomainProvider)),
			dirkaccountmanager.WithRANDAODomainProvider(eth2Client.(eth2client.RANDAODomainProvider)),
			dirkaccountmanager.WithSelectionProofDomainProvider(eth2Client.(eth2client.SelectionProofDomainProvider)),
			dirkaccountmanager.WithAggregateAndProofDomainProvider(eth2Client.(eth2client.AggregateAndProofDomainProvider)),
			dirkaccountmanager.WithSignatureDomainProvider(eth2Client.(eth2client.SignatureDomainProvider)),
			dirkaccountmanager.WithClientCert(certPEMBlock),
			dirkaccountmanager.WithClientKey(keyPEMBlock),
			dirkaccountmanager.WithCACert(caPEMBlock),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start dirk account manager service")
		}
	}

	if viper.Get("accountmanager.wallet") != nil {
		var err error
		passphrases := make([][]byte, 0)
		for _, passphraseURL := range viper.GetStringSlice("accountmanager.wallet.passphrases") {
			passphrase, err := majordomo.Fetch(ctx, passphraseURL)
			if err != nil {
				log.Error().Err(err).Str("url", string(passphrase)).Msg("failed to obtain passphrase")
				continue
			}
			passphrases = append(passphrases, passphrase)
		}
		if len(passphrases) == 0 {
			return nil, errors.New("no passphrases for wallet supplied")
		}
		accountManager, err = walletaccountmanager.New(ctx,
			walletaccountmanager.WithLogLevel(logLevel(viper.GetString("accountmanager.wallet.log-level"))),
			walletaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			walletaccountmanager.WithValidatorsProvider(eth2Client.(eth2client.ValidatorsProvider)),
			walletaccountmanager.WithAccountPaths(viper.GetStringSlice("accountmanager.wallet.accounts")),
			walletaccountmanager.WithPassphrases(passphrases),
			walletaccountmanager.WithLocations(viper.GetStringSlice("accountmanager.wallet.locations")),
			walletaccountmanager.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
			walletaccountmanager.WithBeaconProposerDomainProvider(eth2Client.(eth2client.BeaconProposerDomainProvider)),
			walletaccountmanager.WithBeaconAttesterDomainProvider(eth2Client.(eth2client.BeaconAttesterDomainProvider)),
			walletaccountmanager.WithRANDAODomainProvider(eth2Client.(eth2client.RANDAODomainProvider)),
			walletaccountmanager.WithSelectionProofDomainProvider(eth2Client.(eth2client.SelectionProofDomainProvider)),
			walletaccountmanager.WithAggregateAndProofDomainProvider(eth2Client.(eth2client.AggregateAndProofDomainProvider)),
			walletaccountmanager.WithSignatureDomainProvider(eth2Client.(eth2client.SignatureDomainProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start wallet account manager service")
		}
	}

	return accountManager, nil
}

func selectBeaconBlockProposalProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (eth2client.BeaconBlockProposalProvider, error) {
	var beaconBlockProposalProvider eth2client.BeaconBlockProposalProvider
	var err error
	switch viper.GetString("strategies.beaconblockproposal.style") {
	case "best":
		log.Info().Msg("Starting best beacon block proposal strategy")
		beaconBlockProposalProviders := make(map[string]eth2client.BeaconBlockProposalProvider)
		for _, address := range viper.GetStringSlice("strategies.beaconblockproposal.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %q for beacon block proposal strategy", address))
			}
			beaconBlockProposalProviders[address] = client.(eth2client.BeaconBlockProposalProvider)
		}
		beaconBlockProposalProvider, err = bestbeaconblockproposalstrategy.New(ctx,
			bestbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestbeaconblockproposalstrategy.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			bestbeaconblockproposalstrategy.WithLogLevel(logLevel(viper.GetString("strategies.beaconblockproposal.log-level"))),
			bestbeaconblockproposalstrategy.WithBeaconBlockProposalProviders(beaconBlockProposalProviders),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best beacon block proposal strategy")
		}
	case "first":
		log.Info().Msg("Starting first beacon block proposal strategy")
		beaconBlockProposalProviders := make(map[string]eth2client.BeaconBlockProposalProvider)
		for _, address := range viper.GetStringSlice("strategies.beaconblockproposal.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %q for beacon block proposal strategy", address))
			}
			beaconBlockProposalProviders[address] = client.(eth2client.BeaconBlockProposalProvider)
		}
		beaconBlockProposalProvider, err = firstbeaconblockproposalstrategy.New(ctx,
			firstbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstbeaconblockproposalstrategy.WithLogLevel(logLevel(viper.GetString("strategies.beaconblockproposal.log-level"))),
			firstbeaconblockproposalstrategy.WithBeaconBlockProposalProviders(beaconBlockProposalProviders),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first beacon block proposal strategy")
		}
	default:
		log.Info().Msg("Starting simple beacon block proposal strategy")
		beaconBlockProposalProvider = eth2Client.(eth2client.BeaconBlockProposalProvider)
	}

	return beaconBlockProposalProvider, nil
}

func selectSubmitterStrategy(ctx context.Context, eth2Client eth2client.Service) (submitter.Service, error) {
	var submitter submitter.Service
	var err error
	switch viper.GetString("strategies.submitter.style") {
	case "all":
		log.Info().Msg("Starting multinode submitter strategy")
		beaconBlockSubmitters := make(map[string]eth2client.BeaconBlockSubmitter)
		attestationSubmitters := make(map[string]eth2client.AttestationSubmitter)
		aggregateAttestationSubmitters := make(map[string]eth2client.AggregateAttestationsSubmitter)
		beaconCommitteeSubscriptionsSubmitters := make(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter)
		for _, address := range viper.GetStringSlice("strategies.submitter.all.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %q for submitter strategy", address))
			}
			beaconBlockSubmitters[address] = client.(eth2client.BeaconBlockSubmitter)
			attestationSubmitters[address] = client.(eth2client.AttestationSubmitter)
			aggregateAttestationSubmitters[address] = client.(eth2client.AggregateAttestationsSubmitter)
		}
		submitter, err = multinodesubmitter.New(ctx,
			multinodesubmitter.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			multinodesubmitter.WithLogLevel(logLevel(viper.GetString("strategies.submitter.log-level"))),
			multinodesubmitter.WithBeaconBlockSubmitters(beaconBlockSubmitters),
			multinodesubmitter.WithAttestationSubmitters(attestationSubmitters),
			multinodesubmitter.WithAggregateAttestationsSubmitters(aggregateAttestationSubmitters),
			multinodesubmitter.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
		)
	default:
		log.Info().Msg("Starting standard submitter strategy")
		submitter, err = immediatesubmitter.New(ctx,
			immediatesubmitter.WithLogLevel(logLevel(viper.GetString("strategies.submitter.log-level"))),
			immediatesubmitter.WithBeaconBlockSubmitter(eth2Client.(eth2client.BeaconBlockSubmitter)),
			immediatesubmitter.WithAttestationSubmitter(eth2Client.(eth2client.AttestationSubmitter)),
			immediatesubmitter.WithBeaconCommitteeSubscriptionsSubmitter(eth2Client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)),
			immediatesubmitter.WithAggregateAttestationsSubmitter(eth2Client.(eth2client.AggregateAttestationsSubmitter)),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start submitter service")
	}
	return submitter, nil
}
