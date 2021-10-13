// Copyright © 2020, 2021 Attestant Limited.
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

	// #nosec G108
	_ "net/http/pprof"
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
	"github.com/attestantio/vouch/services/chaintime"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	standardcontroller "github.com/attestantio/vouch/services/controller/standard"
	"github.com/attestantio/vouch/services/graffitiprovider"
	dynamicgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/dynamic"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/services/scheduler"
	advancedscheduler "github.com/attestantio/vouch/services/scheduler/advanced"
	basicscheduler "github.com/attestantio/vouch/services/scheduler/basic"
	"github.com/attestantio/vouch/services/signer"
	standardsigner "github.com/attestantio/vouch/services/signer/standard"
	"github.com/attestantio/vouch/services/submitter"
	immediatesubmitter "github.com/attestantio/vouch/services/submitter/immediate"
	multinodesubmitter "github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	standardsynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/standard"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	standardsynccommitteemessenger "github.com/attestantio/vouch/services/synccommitteemessenger/standard"
	"github.com/attestantio/vouch/services/synccommitteesubscriber"
	standardsynccommitteesubscriber "github.com/attestantio/vouch/services/synccommitteesubscriber/standard"
	"github.com/attestantio/vouch/services/validatorsmanager"
	standardvalidatorsmanager "github.com/attestantio/vouch/services/validatorsmanager/standard"
	bestaggregateattestationstrategy "github.com/attestantio/vouch/strategies/aggregateattestation/best"
	firstaggregateattestationstrategy "github.com/attestantio/vouch/strategies/aggregateattestation/first"
	bestattestationdatastrategy "github.com/attestantio/vouch/strategies/attestationdata/best"
	firstattestationdatastrategy "github.com/attestantio/vouch/strategies/attestationdata/first"
	bestbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	firstbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	bestsynccommitteecontributionstrategy "github.com/attestantio/vouch/strategies/synccommitteecontribution/best"
	firstsynccommitteecontributionstrategy "github.com/attestantio/vouch/strategies/synccommitteecontribution/first"
	"github.com/attestantio/vouch/util"
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

// ReleaseVersion is the release version for the code.
var ReleaseVersion = "1.2.0"

func main() {
	os.Exit(main2())
}

func main2() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fetchConfig(); err != nil {
		zerologger.Error().Err(err).Msg("Failed to fetch configuration")
		return 1
	}

	majordomo, err := initMajordomo(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise majordomo")
		return 1
	}

	// runCommands will not return if a command is run.
	runCommands(ctx, majordomo)

	if err := initLogging(); err != nil {
		log.Error().Err(err).Msg("Failed to initialise logging")
		return 1
	}

	logModules()
	log.Info().Str("version", ReleaseVersion).Msg("Starting vouch")

	if err := initProfiling(); err != nil {
		log.Error().Err(err).Msg("Failed to initialise profiling")
		return 1
	}

	closer, err := initTracing()
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise tracing")
		return 1
	}
	if closer != nil {
		defer closer.Close()
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 8)

	if err := e2types.InitBLS(); err != nil {
		log.Error().Err(err).Msg("Failed to initialise BLS library")
		return 1
	}

	if err := startServices(ctx, majordomo); err != nil {
		log.Error().Err(err).Msg("Failed to initialise services")
		return 1
	}
	setReady(ctx, true)
	log.Info().Msg("All services operational")

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	for {
		sig := <-sigCh
		if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == os.Interrupt || sig == os.Kill {
			break
		}
	}

	log.Info().Msg("Stopping vouch")
	return 0
}

// fetchConfig fetches configuration from various sources.
func fetchConfig() error {
	pflag.String("base-dir", "", "base directory for configuration files")
	pflag.String("log-level", "info", "minimum level of messsages to log")
	pflag.String("log-file", "", "redirect log output to a file")
	pflag.String("profile-address", "", "Address on which to run Go profile server")
	pflag.String("tracing-address", "", "Address to which to send tracing data")
	pflag.String("beacon-node-address", "localhost:4000", "Address on which to contact the beacon node")
	pflag.Bool("version", false, "show Vouch version and exit")
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
	viper.SetDefault("process-concurrency", int64(runtime.GOMAXPROCS(-1)))
	viper.SetDefault("strategies.timeout", 2*time.Second)
	viper.SetDefault("eth2client.timeout", 2*time.Minute)
	viper.SetDefault("controller.max-attestation-delay", 4*time.Second)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return errors.New("failed to read configuration file")
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
	if err := registerMetrics(ctx, monitor); err != nil {
		return errors.Wrap(err, "failed to register metrics")
	}
	setRelease(ctx, ReleaseVersion)
	setReady(ctx, false)

	log.Trace().Msg("Starting Ethereum 2 client service")
	eth2Client, err := fetchClient(ctx, viper.GetString("beacon-node-address"))
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to fetch client %s", viper.GetString("beacon-node-address")))
	}

	log.Trace().Msg("Starting chain time service")
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(util.LogLevel("chaintime")),
		standardchaintime.WithGenesisTimeProvider(eth2Client.(eth2client.GenesisTimeProvider)),
		standardchaintime.WithSlotDurationProvider(eth2Client.(eth2client.SlotDurationProvider)),
		standardchaintime.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start chain time service")
	}

	log.Trace().Msg("Selecting scheduler")
	scheduler, err := selectScheduler(ctx, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to select scheduler")
	}

	log.Trace().Msg("Starting validators manager")
	validatorsManager, err := startValidatorsManager(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to start validators manager")
	}

	log.Trace().Msg("Starting signer")
	signerSvc, err := startSigner(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to start signer")
	}

	log.Trace().Msg("Starting account manager")
	accountManager, err := startAccountManager(ctx, monitor, eth2Client, validatorsManager, majordomo, chainTime)
	if err != nil {
		return errors.Wrap(err, "failed to start account manager")
	}

	log.Trace().Msg("Selecting submitter strategy")
	submitterStrategy, err := selectSubmitterStrategy(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to select submitter")
	}

	log.Trace().Msg("Starting graffiti provider")
	graffitiProvider, err := startGraffitiProvider(ctx, majordomo)
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
		standardbeaconblockproposer.WithLogLevel(util.LogLevel("beaconblockproposer")),
		standardbeaconblockproposer.WithChainTimeService(chainTime),
		standardbeaconblockproposer.WithProposalDataProvider(beaconBlockProposalProvider),
		standardbeaconblockproposer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardbeaconblockproposer.WithGraffitiProvider(graffitiProvider),
		standardbeaconblockproposer.WithMonitor(monitor.(metrics.BeaconBlockProposalMonitor)),
		standardbeaconblockproposer.WithBeaconBlockSubmitter(submitterStrategy.(submitter.BeaconBlockSubmitter)),
		standardbeaconblockproposer.WithRANDAORevealSigner(signerSvc.(signer.RANDAORevealSigner)),
		standardbeaconblockproposer.WithBeaconBlockSigner(signerSvc.(signer.BeaconBlockSigner)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon block proposer service")
	}

	log.Trace().Msg("Selecting attestation data provider")
	attestationDataProvider, err := selectAttestationDataProvider(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to select attestation data provider")
	}

	log.Trace().Msg("Starting attester")
	attester, err := standardattester.New(ctx,
		standardattester.WithLogLevel(util.LogLevel("attester")),
		standardattester.WithProcessConcurrency(util.ProcessConcurrency("attester")),
		standardattester.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
		standardattester.WithAttestationDataProvider(attestationDataProvider),
		standardattester.WithAttestationsSubmitter(submitterStrategy.(submitter.AttestationsSubmitter)),
		standardattester.WithMonitor(monitor.(metrics.AttestationMonitor)),
		standardattester.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardattester.WithBeaconAttestationsSigner(signerSvc.(signer.BeaconAttestationsSigner)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start attester service")
	}

	log.Trace().Msg("Selecting aggregate attestation provider")
	aggregateAttestationProvider, err := selectAggregateAttestationProvider(ctx, monitor, eth2Client)
	if err != nil {
		return errors.Wrap(err, "failed to select aggregate attestation provider")
	}

	log.Trace().Msg("Starting beacon attestation aggregator")
	attestationAggregator, err := standardattestationaggregator.New(ctx,
		standardattestationaggregator.WithLogLevel(util.LogLevel("attestationaggregator")),
		standardattestationaggregator.WithTargetAggregatorsPerCommitteeProvider(eth2Client.(eth2client.TargetAggregatorsPerCommitteeProvider)),
		standardattestationaggregator.WithAggregateAttestationProvider(aggregateAttestationProvider),
		standardattestationaggregator.WithAggregateAttestationsSubmitter(submitterStrategy.(submitter.AggregateAttestationsSubmitter)),
		standardattestationaggregator.WithMonitor(monitor.(metrics.AttestationAggregationMonitor)),
		standardattestationaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardattestationaggregator.WithSlotSelectionSigner(signerSvc.(signer.SlotSelectionSigner)),
		standardattestationaggregator.WithAggregateAndProofSigner(signerSvc.(signer.AggregateAndProofSigner)),
		standardattestationaggregator.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon attestation aggregator service")
	}

	log.Trace().Msg("Starting beacon committee subscriber service")
	beaconCommitteeSubscriber, err := standardbeaconcommitteesubscriber.New(ctx,
		standardbeaconcommitteesubscriber.WithLogLevel(util.LogLevel("beaconcommiteesubscriber")),
		standardbeaconcommitteesubscriber.WithProcessConcurrency(util.ProcessConcurrency("beaconcommitteesubscriber")),
		standardbeaconcommitteesubscriber.WithMonitor(monitor.(metrics.BeaconCommitteeSubscriptionMonitor)),
		standardbeaconcommitteesubscriber.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardbeaconcommitteesubscriber.WithAttestationAggregator(attestationAggregator),
		standardbeaconcommitteesubscriber.WithBeaconCommitteeSubmitter(submitterStrategy.(submitter.BeaconCommitteeSubscriptionsSubmitter)),
	)
	if err != nil {
		return errors.Wrap(err, "failed to start beacon committee subscriber service")
	}

	// Decide if the ETH2 client is capable of Altair.
	altairCapable := false
	spec, err := eth2Client.(eth2client.SpecProvider).Spec(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to obtain spec")
	}
	if _, exists := spec["INACTIVITY_PENALTY_QUOTIENT_ALTAIR"]; exists {
		altairCapable = true
		log.Info().Msg("Client is Altair-capable")
	} else {
		log.Info().Msg("Client is not Altair-capable")
	}

	// The following items are for Altair.  These are optional.
	var syncCommitteeSubscriber synccommitteesubscriber.Service
	var syncCommitteeMessenger synccommitteemessenger.Service
	var syncCommitteeAggregator synccommitteeaggregator.Service
	if altairCapable {
		log.Trace().Msg("Starting sync committee subscriber service")
		syncCommitteeSubscriber, err = standardsynccommitteesubscriber.New(ctx,
			standardsynccommitteesubscriber.WithLogLevel(util.LogLevel("synccommiteesubscriber")),
			standardsynccommitteesubscriber.WithMonitor(monitor.(metrics.SyncCommitteeSubscriptionMonitor)),
			standardsynccommitteesubscriber.WithSyncCommitteeSubmitter(submitterStrategy.(submitter.SyncCommitteeSubscriptionsSubmitter)),
		)
		if err != nil {
			return errors.Wrap(err, "failed to start beacon committee subscriber service")
		}

		log.Trace().Msg("Selecting sync committee contribution provider")
		syncCommitteeContributionProvider, err := selectSyncCommitteeContributionProvider(ctx, monitor, eth2Client)
		if err != nil {
			return errors.Wrap(err, "failed to select sync committee contribution provider")
		}

		log.Trace().Msg("Starting sync committee aggregator")
		syncCommitteeAggregator, err = standardsynccommitteeaggregator.New(ctx,
			standardsynccommitteeaggregator.WithLogLevel(util.LogLevel("synccommitteeaggregator")),
			standardsynccommitteeaggregator.WithMonitor(monitor.(metrics.SyncCommitteeAggregationMonitor)),
			standardsynccommitteeaggregator.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			standardsynccommitteeaggregator.WithBeaconBlockRootProvider(eth2Client.(eth2client.BeaconBlockRootProvider)),
			standardsynccommitteeaggregator.WithContributionAndProofSigner(signerSvc.(signer.ContributionAndProofSigner)),
			standardsynccommitteeaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
			standardsynccommitteeaggregator.WithSyncCommitteeContributionProvider(syncCommitteeContributionProvider),
			standardsynccommitteeaggregator.WithSyncCommitteeContributionsSubmitter(submitterStrategy.(submitter.SyncCommitteeContributionsSubmitter)),
		)
		if err != nil {
			return errors.Wrap(err, "failed to start sync committee aggregator service")
		}

		log.Trace().Msg("Starting sync committee messenger")
		syncCommitteeMessenger, err = standardsynccommitteemessenger.New(ctx,
			standardsynccommitteemessenger.WithLogLevel(util.LogLevel("synccommitteemessenger")),
			standardsynccommitteemessenger.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			standardsynccommitteemessenger.WithMonitor(monitor.(metrics.SyncCommitteeMessageMonitor)),
			standardsynccommitteemessenger.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			standardsynccommitteemessenger.WithChainTimeService(chainTime),
			standardsynccommitteemessenger.WithSyncCommitteeAggregator(syncCommitteeAggregator),
			standardsynccommitteemessenger.WithBeaconBlockRootProvider(eth2Client.(eth2client.BeaconBlockRootProvider)),
			standardsynccommitteemessenger.WithSyncCommitteeMessagesSubmitter(submitterStrategy.(submitter.SyncCommitteeMessagesSubmitter)),
			standardsynccommitteemessenger.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
			standardsynccommitteemessenger.WithSyncCommitteeRootSigner(signerSvc.(signer.SyncCommitteeRootSigner)),
			standardsynccommitteemessenger.WithSyncCommitteeSelectionSigner(signerSvc.(signer.SyncCommitteeSelectionSigner)),
			standardsynccommitteemessenger.WithSyncCommitteeSubscriptionsSubmitter(submitterStrategy.(submitter.SyncCommitteeSubscriptionsSubmitter)),
		)
		if err != nil {
			return errors.Wrap(err, "failed to start sync committee messenger service")
		}
	}

	log.Trace().Msg("Starting controller")
	_, err = standardcontroller.New(ctx,
		standardcontroller.WithLogLevel(util.LogLevel("controller")),
		standardcontroller.WithMonitor(monitor.(metrics.ControllerMonitor)),
		standardcontroller.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardcontroller.WithForkScheduleProvider(eth2Client.(eth2client.ForkScheduleProvider)),
		standardcontroller.WithChainTimeService(chainTime),
		standardcontroller.WithProposerDutiesProvider(eth2Client.(eth2client.ProposerDutiesProvider)),
		standardcontroller.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardcontroller.WithSyncCommitteeDutiesProvider(eth2Client.(eth2client.SyncCommitteeDutiesProvider)),
		standardcontroller.WithEventsProvider(eth2Client.(eth2client.EventsProvider)),
		standardcontroller.WithScheduler(scheduler),
		standardcontroller.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardcontroller.WithAttester(attester),
		standardcontroller.WithSyncCommitteeMessenger(syncCommitteeMessenger),
		standardcontroller.WithSyncCommitteeAggregator(syncCommitteeAggregator),
		standardcontroller.WithBeaconBlockProposer(beaconBlockProposer),
		standardcontroller.WithAttestationAggregator(attestationAggregator),
		standardcontroller.WithBeaconCommitteeSubscriber(beaconCommitteeSubscriber),
		standardcontroller.WithSyncCommitteeSubscriber(syncCommitteeSubscriber),
		standardcontroller.WithAccountsRefresher(accountManager.(accountmanager.Refresher)),
		standardcontroller.WithMaxAttestationDelay(viper.GetDuration("controller.max-attestation-delay")),
		standardcontroller.WithMaxSyncCommitteeMessageDelay(viper.GetDuration("controller.max-sync-committee-message-delay")),
		standardcontroller.WithReorgs(viper.GetBool("controller.reorgs")),
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
		standardmajordomo.WithLogLevel(util.LogLevel("majordomo")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create majordomo service")
	}

	directConfidant, err := directconfidant.New(ctx,
		directconfidant.WithLogLevel(util.LogLevel("majordomo.confidants.direct")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create direct confidant")
	}
	if err := majordomo.RegisterConfidant(ctx, directConfidant); err != nil {
		return nil, errors.Wrap(err, "failed to register direct confidant")
	}

	fileConfidant, err := fileconfidant.New(ctx,
		fileconfidant.WithLogLevel(util.LogLevel("majordomo.confidants.file")),
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
			asmconfidant.WithLogLevel(util.LogLevel("majordomo.confidants.asm")),
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
			gsmconfidant.WithLogLevel(util.LogLevel("majordomo.confidants.gsm")),
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
			prometheusmetrics.WithLogLevel(util.LogLevel("metrics.prometheus")),
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

func selectScheduler(ctx context.Context, monitor metrics.Service) (scheduler.Service, error) {
	var scheduler scheduler.Service
	var err error
	switch viper.GetString("scheduler.style") {
	case "advanced":
		log.Info().Msg("Starting advanced scheduler")
		scheduler, err = advancedscheduler.New(ctx,
			advancedscheduler.WithLogLevel(util.LogLevel("scheduler.advanced")),
			advancedscheduler.WithMonitor(monitor.(metrics.SchedulerMonitor)),
		)
	default:
		log.Info().Msg("Starting basic scheduler")
		scheduler, err = basicscheduler.New(ctx,
			basicscheduler.WithLogLevel(util.LogLevel("scheduler.basic")),
			basicscheduler.WithMonitor(monitor.(metrics.SchedulerMonitor)),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start scheduler service")
	}
	return scheduler, nil
}

func startGraffitiProvider(ctx context.Context, majordomo majordomo.Service) (graffitiprovider.Service, error) {
	switch {
	case viper.Get("graffiti.dynamic") != nil:
		log.Info().Msg("Starting dynamic graffiti provider")
		return dynamicgraffitiprovider.New(ctx,
			dynamicgraffitiprovider.WithMajordomo(majordomo),
			dynamicgraffitiprovider.WithLogLevel(util.LogLevel("graffiti.dynamic")),
			dynamicgraffitiprovider.WithLocation(viper.GetString("graffiti.dynamic.location")),
		)
	default:
		log.Info().Msg("Starting static graffiti provider")
		return staticgraffitiprovider.New(ctx,
			staticgraffitiprovider.WithLogLevel(util.LogLevel("graffiti.static")),
			staticgraffitiprovider.WithGraffiti([]byte(viper.GetString("graffiti.static.value"))),
		)
	}
}

func startValidatorsManager(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service) (validatorsmanager.Service, error) {
	farFutureEpoch, err := eth2Client.(eth2client.FarFutureEpochProvider).FarFutureEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain far future epoch")
	}
	validatorsManager, err := standardvalidatorsmanager.New(ctx,
		standardvalidatorsmanager.WithLogLevel(util.LogLevel("validatorsmanager")),
		standardvalidatorsmanager.WithMonitor(monitor.(metrics.ValidatorsManagerMonitor)),
		standardvalidatorsmanager.WithClientMonitor(monitor.(metrics.ClientMonitor)),
		standardvalidatorsmanager.WithValidatorsProvider(eth2Client.(eth2client.ValidatorsProvider)),
		standardvalidatorsmanager.WithFarFutureEpoch(farFutureEpoch),
	)

	if err != nil {
		return nil, errors.Wrap(err, "failed to start standard validators manager service")
	}
	return validatorsManager, nil
}

func startSigner(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service) (signer.Service, error) {
	signer, err := standardsigner.New(ctx,
		standardsigner.WithLogLevel(util.LogLevel("signer")),
		standardsigner.WithMonitor(monitor.(metrics.SignerMonitor)),
		standardsigner.WithClientMonitor(monitor.(metrics.ClientMonitor)),
		standardsigner.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardsigner.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
	)

	if err != nil {
		return nil, errors.Wrap(err, "failed to start signer provider service")
	}
	return signer, nil
}

func startAccountManager(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service, validatorsManager validatorsmanager.Service, majordomo majordomo.Service, chainTime chaintime.Service) (accountmanager.Service, error) {
	var accountManager accountmanager.Service
	if viper.Get("accountmanager.dirk") != nil {
		log.Info().Msg("Starting dirk account manager")
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
			dirkaccountmanager.WithLogLevel(util.LogLevel("accountmanager.dirk")),
			dirkaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			dirkaccountmanager.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			dirkaccountmanager.WithProcessConcurrency(util.ProcessConcurrency("accountmanager.dirk")),
			dirkaccountmanager.WithValidatorsManager(validatorsManager),
			dirkaccountmanager.WithEndpoints(viper.GetStringSlice("accountmanager.dirk.endpoints")),
			dirkaccountmanager.WithAccountPaths(viper.GetStringSlice("accountmanager.dirk.accounts")),
			dirkaccountmanager.WithClientCert(certPEMBlock),
			dirkaccountmanager.WithClientKey(keyPEMBlock),
			dirkaccountmanager.WithCACert(caPEMBlock),
			dirkaccountmanager.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
			dirkaccountmanager.WithFarFutureEpochProvider(eth2Client.(eth2client.FarFutureEpochProvider)),
			dirkaccountmanager.WithCurrentEpochProvider(chainTime),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start dirk account manager service")
		}
		return accountManager, nil
	}

	if viper.Get("accountmanager.wallet") != nil {
		log.Info().Msg("Starting wallet account manager")
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
			walletaccountmanager.WithLogLevel(util.LogLevel("accountmanager.wallet")),
			walletaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			walletaccountmanager.WithProcessConcurrency(util.ProcessConcurrency("accountmanager.wallet")),
			walletaccountmanager.WithValidatorsManager(validatorsManager),
			walletaccountmanager.WithAccountPaths(viper.GetStringSlice("accountmanager.wallet.accounts")),
			walletaccountmanager.WithPassphrases(passphrases),
			walletaccountmanager.WithLocations(viper.GetStringSlice("accountmanager.wallet.locations")),
			walletaccountmanager.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
			walletaccountmanager.WithFarFutureEpochProvider(eth2Client.(eth2client.FarFutureEpochProvider)),
			walletaccountmanager.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
			walletaccountmanager.WithCurrentEpochProvider(chainTime),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start wallet account manager service")
		}
		return accountManager, nil
	}

	return nil, errors.New("no account manager defined")
}

func selectAttestationDataProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (eth2client.AttestationDataProvider, error) {
	var attestationDataProvider eth2client.AttestationDataProvider
	var err error
	switch viper.GetString("strategies.attestationdata.style") {
	case "best":
		log.Info().Msg("Starting best attestation data strategy")
		attestationDataProviders := make(map[string]eth2client.AttestationDataProvider)
		for _, address := range viper.GetStringSlice("strategies.attestationdata.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for attestation data strategy", address))
			}
			attestationDataProviders[address] = client.(eth2client.AttestationDataProvider)
		}
		attestationDataProvider, err = bestattestationdatastrategy.New(ctx,
			bestattestationdatastrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestattestationdatastrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.attestationdata.best")),
			bestattestationdatastrategy.WithLogLevel(util.LogLevel("strategies.attestationdata.best")),
			bestattestationdatastrategy.WithAttestationDataProviders(attestationDataProviders),
			bestattestationdatastrategy.WithTimeout(util.Timeout("strategies.attestationdata.best")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best attestation data strategy")
		}
	case "first":
		log.Info().Msg("Starting first attestation data strategy")
		attestationDataProviders := make(map[string]eth2client.AttestationDataProvider)
		for _, address := range viper.GetStringSlice("strategies.attestationdata.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for attestation data strategy", address))
			}
			attestationDataProviders[address] = client.(eth2client.AttestationDataProvider)
		}
		attestationDataProvider, err = firstattestationdatastrategy.New(ctx,
			firstattestationdatastrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstattestationdatastrategy.WithLogLevel(util.LogLevel("strategies.attestationdata.first")),
			firstattestationdatastrategy.WithAttestationDataProviders(attestationDataProviders),
			firstattestationdatastrategy.WithTimeout(util.Timeout("strategies.attestationdata.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first attestation data strategy")
		}
	default:
		log.Info().Msg("Starting simple attestation data strategy")
		attestationDataProvider = eth2Client.(eth2client.AttestationDataProvider)
	}

	return attestationDataProvider, nil
}

func selectAggregateAttestationProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (
	eth2client.AggregateAttestationProvider,
	error,
) {
	var aggregateAttestationProvider eth2client.AggregateAttestationProvider
	var err error
	switch viper.GetString("strategies.aggregateattestation.style") {
	case "best":
		log.Info().Msg("Starting best aggregate attestation strategy")
		aggregateAttestationProviders := make(map[string]eth2client.AggregateAttestationProvider)
		for _, address := range viper.GetStringSlice("strategies.aggregateattestation.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for aggregate attestation strategy", address))
			}
			aggregateAttestationProviders[address] = client.(eth2client.AggregateAttestationProvider)
		}
		aggregateAttestationProvider, err = bestaggregateattestationstrategy.New(ctx,
			bestaggregateattestationstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestaggregateattestationstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.aggregateattestation.best")),
			bestaggregateattestationstrategy.WithLogLevel(util.LogLevel("strategies.aggregateattestation.best")),
			bestaggregateattestationstrategy.WithAggregateAttestationProviders(aggregateAttestationProviders),
			bestaggregateattestationstrategy.WithTimeout(util.Timeout("strategies.aggregateattestation.best")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best aggregate attestation strategy")
		}
	case "first":
		log.Info().Msg("Starting first aggregate attestation strategy")
		aggregateAttestationProviders := make(map[string]eth2client.AggregateAttestationProvider)
		for _, address := range viper.GetStringSlice("strategies.aggregateattestation.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for aggregate attestation strategy", address))
			}
			aggregateAttestationProviders[address] = client.(eth2client.AggregateAttestationProvider)
		}
		aggregateAttestationProvider, err = firstaggregateattestationstrategy.New(ctx,
			firstaggregateattestationstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstaggregateattestationstrategy.WithLogLevel(util.LogLevel("strategies.aggregateattestation.first")),
			firstaggregateattestationstrategy.WithAggregateAttestationProviders(aggregateAttestationProviders),
			firstaggregateattestationstrategy.WithTimeout(util.Timeout("strategies.aggregateattestation.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first aggregate attestation strategy")
		}
	default:
		log.Info().Msg("Starting simple aggregate attestation strategy")
		aggregateAttestationProvider = eth2Client.(eth2client.AggregateAttestationProvider)
	}

	return aggregateAttestationProvider, nil
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
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block proposal strategy", address))
			}
			beaconBlockProposalProviders[address] = client.(eth2client.BeaconBlockProposalProvider)
		}
		beaconBlockProposalProvider, err = bestbeaconblockproposalstrategy.New(ctx,
			bestbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestbeaconblockproposalstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.beaconblockproposal.best")),
			bestbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockproposal.best")),
			bestbeaconblockproposalstrategy.WithBeaconBlockProposalProviders(beaconBlockProposalProviders),
			bestbeaconblockproposalstrategy.WithSignedBeaconBlockProvider(eth2Client.(eth2client.SignedBeaconBlockProvider)),
			bestbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.beaconblockproposal.best")),
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
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block proposal strategy", address))
			}
			beaconBlockProposalProviders[address] = client.(eth2client.BeaconBlockProposalProvider)
		}
		beaconBlockProposalProvider, err = firstbeaconblockproposalstrategy.New(ctx,
			firstbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockproposal.first")),
			firstbeaconblockproposalstrategy.WithBeaconBlockProposalProviders(beaconBlockProposalProviders),
			firstbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.beaconblockproposal.first")),
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

func selectSyncCommitteeContributionProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (eth2client.SyncCommitteeContributionProvider, error) {
	var syncCommitteeContributionProvider eth2client.SyncCommitteeContributionProvider
	var err error
	switch viper.GetString("strategies.synccommitteecontribution.style") {
	case "best":
		log.Info().Msg("Starting best sync committee contribution strategy")
		syncCommitteeContributionProviders := make(map[string]eth2client.SyncCommitteeContributionProvider)
		for _, address := range viper.GetStringSlice("strategies.synccommitteecontribution.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for sync committee contribution strategy", address))
			}
			syncCommitteeContributionProviders[address] = client.(eth2client.SyncCommitteeContributionProvider)
		}
		syncCommitteeContributionProvider, err = bestsynccommitteecontributionstrategy.New(ctx,
			bestsynccommitteecontributionstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestsynccommitteecontributionstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.synccommitteecontribution.best")),
			bestsynccommitteecontributionstrategy.WithLogLevel(util.LogLevel("strategies.synccommitteecontribution.best")),
			bestsynccommitteecontributionstrategy.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			bestsynccommitteecontributionstrategy.WithTimeout(util.Timeout("strategies.synccommitteecontribution.best")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best sync committee contribution strategy")
		}
	case "first":
		log.Info().Msg("Starting first sync committee contribution strategy")
		syncCommitteeContributionProviders := make(map[string]eth2client.SyncCommitteeContributionProvider)
		for _, address := range viper.GetStringSlice("strategies.synccommitteecontribution.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for sync committee contribution strategy", address))
			}
			syncCommitteeContributionProviders[address] = client.(eth2client.SyncCommitteeContributionProvider)
		}
		syncCommitteeContributionProvider, err = firstsynccommitteecontributionstrategy.New(ctx,
			firstsynccommitteecontributionstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstsynccommitteecontributionstrategy.WithLogLevel(util.LogLevel("strategies.synccommitteecontribution.first")),
			firstsynccommitteecontributionstrategy.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			firstsynccommitteecontributionstrategy.WithTimeout(util.Timeout("strategies.synccommitteecontribution.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first sync committee contribution strategy")
		}
	default:
		log.Info().Msg("Starting simple sync committee contribution strategy")
		syncCommitteeContributionProvider = eth2Client.(eth2client.SyncCommitteeContributionProvider)
	}

	return syncCommitteeContributionProvider, nil
}

func selectSubmitterStrategy(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service) (submitter.Service, error) {
	var submitter submitter.Service
	var err error
	switch viper.GetString("submitter.style") {
	case "all", "multinode":
		log.Info().Msg("Starting multinode submitter strategy")
		beaconBlockSubmitters := make(map[string]eth2client.BeaconBlockSubmitter)
		attestationsSubmitters := make(map[string]eth2client.AttestationsSubmitter)
		aggregateAttestationSubmitters := make(map[string]eth2client.AggregateAttestationsSubmitter)
		beaconCommitteeSubscriptionsSubmitters := make(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter)
		syncCommitteeMessagesSubmitters := make(map[string]eth2client.SyncCommitteeMessagesSubmitter)
		syncCommitteeContributionsSubmitters := make(map[string]eth2client.SyncCommitteeContributionsSubmitter)
		syncCommitteeSubscriptionsSubmitters := make(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter)
		for _, address := range viper.GetStringSlice("submitter.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for submitter strategy", address))
			}
			beaconBlockSubmitters[address] = client.(eth2client.BeaconBlockSubmitter)
			attestationsSubmitters[address] = client.(eth2client.AttestationsSubmitter)
			aggregateAttestationSubmitters[address] = client.(eth2client.AggregateAttestationsSubmitter)
			beaconCommitteeSubscriptionsSubmitters[address] = client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)
			syncCommitteeMessagesSubmitters[address] = client.(eth2client.SyncCommitteeMessagesSubmitter)
			syncCommitteeContributionsSubmitters[address] = client.(eth2client.SyncCommitteeContributionsSubmitter)
			syncCommitteeSubscriptionsSubmitters[address] = client.(eth2client.SyncCommitteeSubscriptionsSubmitter)
		}
		submitter, err = multinodesubmitter.New(ctx,
			multinodesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			multinodesubmitter.WithProcessConcurrency(util.ProcessConcurrency("submitter.multinode")),
			multinodesubmitter.WithLogLevel(util.LogLevel("submitter.multinode")),
			multinodesubmitter.WithBeaconBlockSubmitters(beaconBlockSubmitters),
			multinodesubmitter.WithAttestationsSubmitters(attestationsSubmitters),
			multinodesubmitter.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
			multinodesubmitter.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			multinodesubmitter.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
			multinodesubmitter.WithAggregateAttestationsSubmitters(aggregateAttestationSubmitters),
			multinodesubmitter.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
		)
	default:
		log.Info().Msg("Starting standard submitter strategy")
		submitter, err = immediatesubmitter.New(ctx,
			immediatesubmitter.WithLogLevel(util.LogLevel("submitter.immediate")),
			immediatesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			immediatesubmitter.WithBeaconBlockSubmitter(eth2Client.(eth2client.BeaconBlockSubmitter)),
			immediatesubmitter.WithAttestationsSubmitter(eth2Client.(eth2client.AttestationsSubmitter)),
			immediatesubmitter.WithSyncCommitteeMessagesSubmitter(eth2Client.(eth2client.SyncCommitteeMessagesSubmitter)),
			immediatesubmitter.WithSyncCommitteeContributionsSubmitter(eth2Client.(eth2client.SyncCommitteeContributionsSubmitter)),
			immediatesubmitter.WithSyncCommitteeSubscriptionsSubmitter(eth2Client.(eth2client.SyncCommitteeSubscriptionsSubmitter)),
			immediatesubmitter.WithBeaconCommitteeSubscriptionsSubmitter(eth2Client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)),
			immediatesubmitter.WithAggregateAttestationsSubmitter(eth2Client.(eth2client.AggregateAttestationsSubmitter)),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start submitter service")
	}
	return submitter, nil
}

func runCommands(ctx context.Context, majordomo majordomo.Service) {
	if viper.GetBool("version") {
		fmt.Printf("%s\n", ReleaseVersion)
		os.Exit(0)
	}
}
