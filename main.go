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
	"github.com/attestantio/vouch/services/chaintime"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	standardcontroller "github.com/attestantio/vouch/services/controller/standard"
	"github.com/attestantio/vouch/services/graffitiprovider"
	dynamicgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/dynamic"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	basicscheduler "github.com/attestantio/vouch/services/scheduler/basic"
	"github.com/attestantio/vouch/services/signer"
	standardsigner "github.com/attestantio/vouch/services/signer/standard"
	"github.com/attestantio/vouch/services/submitter"
	immediatesubmitter "github.com/attestantio/vouch/services/submitter/immediate"
	multinodesubmitter "github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/services/validatorsmanager"
	standardvalidatorsmanager "github.com/attestantio/vouch/services/validatorsmanager/standard"
	bestattestationdatastrategy "github.com/attestantio/vouch/strategies/attestationdata/best"
	firstattestationdatastrategy "github.com/attestantio/vouch/strategies/attestationdata/first"
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

// ReleaseVersion is the release version for the code.
var ReleaseVersion = "1.0.4"

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
	viper.Set("process-concurrency", 16)
	viper.Set("eth2client.timeout", 2*time.Minute)

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

	log.Trace().Msg("Starting Ethereum 2 client service")
	eth2Client, err := fetchClient(ctx, viper.GetString("beacon-node-address"))
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to fetch client %s", viper.GetString("beacon-node-address")))
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
		standardbeaconblockproposer.WithLogLevel(logLevel(viper.GetString("beaconblockproposer.log-level"))),
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
		standardattester.WithLogLevel(logLevel(viper.GetString("attester.log-level"))),
		standardattester.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
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

	log.Trace().Msg("Starting beacon attestation aggregator")
	var aggregationAttester standardattestationaggregator.Parameter
	if provider, isProvider := eth2Client.(eth2client.AggregateAttestationProvider); isProvider {
		aggregationAttester = standardattestationaggregator.WithAggregateAttestationDataProvider(provider)
	} else {
		aggregationAttester = standardattestationaggregator.WithPrysmAggregateAttestationDataProvider(eth2Client.(eth2client.PrysmAggregateAttestationProvider))
	}
	attestationAggregator, err := standardattestationaggregator.New(ctx,
		standardattestationaggregator.WithLogLevel(logLevel(viper.GetString("attestationaggregator.log-level"))),
		standardattestationaggregator.WithTargetAggregatorsPerCommitteeProvider(eth2Client.(eth2client.TargetAggregatorsPerCommitteeProvider)),
		aggregationAttester,
		standardattestationaggregator.WithAggregateAttestationsSubmitter(eth2Client.(eth2client.AggregateAttestationsSubmitter)),
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
		standardcontroller.WithEventsProvider(eth2Client.(eth2client.EventsProvider)),
		standardcontroller.WithScheduler(scheduler),
		standardcontroller.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardcontroller.WithAttester(attester),
		standardcontroller.WithBeaconBlockProposer(beaconBlockProposer),
		standardcontroller.WithAttestationAggregator(attestationAggregator),
		standardcontroller.WithBeaconCommitteeSubscriber(beaconCommitteeSubscriber),
		standardcontroller.WithAccountsRefresher(accountManager.(accountmanager.Refresher)),
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

func startGraffitiProvider(ctx context.Context, majordomo majordomo.Service) (graffitiprovider.Service, error) {
	switch {
	case viper.Get("graffiti.dynamic") != nil:
		log.Info().Msg("Starting dynamic graffiti provider")
		return dynamicgraffitiprovider.New(ctx,
			dynamicgraffitiprovider.WithMajordomo(majordomo),
			dynamicgraffitiprovider.WithLogLevel(logLevel(viper.GetString("graffiti.dynamic.log-level"))),
			dynamicgraffitiprovider.WithLocation(viper.GetString("graffiti.dynamic.location")),
		)
	default:
		log.Info().Msg("Starting static graffiti provider")
		return staticgraffitiprovider.New(ctx,
			staticgraffitiprovider.WithLogLevel(logLevel(viper.GetString("graffiti.static.log-level"))),
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
		standardvalidatorsmanager.WithLogLevel(logLevel(viper.GetString("validatorsmanager.log-level"))),
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
		standardsigner.WithLogLevel(logLevel(viper.GetString("signer.log-level"))),
		standardsigner.WithMonitor(monitor.(metrics.SignerMonitor)),
		standardsigner.WithClientMonitor(monitor.(metrics.ClientMonitor)),
		standardsigner.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
		standardsigner.WithBeaconProposerDomainTypeProvider(eth2Client.(eth2client.BeaconProposerDomainProvider)),
		standardsigner.WithBeaconAttesterDomainTypeProvider(eth2Client.(eth2client.BeaconAttesterDomainProvider)),
		standardsigner.WithRANDAODomainTypeProvider(eth2Client.(eth2client.RANDAODomainProvider)),
		standardsigner.WithSelectionProofDomainTypeProvider(eth2Client.(eth2client.SelectionProofDomainProvider)),
		standardsigner.WithAggregateAndProofDomainTypeProvider(eth2Client.(eth2client.AggregateAndProofDomainProvider)),
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
			dirkaccountmanager.WithLogLevel(logLevel(viper.GetString("accountmanager.dirk.log-level"))),
			dirkaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			dirkaccountmanager.WithClientMonitor(monitor.(metrics.ClientMonitor)),
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
			walletaccountmanager.WithLogLevel(logLevel(viper.GetString("accountmanager.wallet.log-level"))),
			walletaccountmanager.WithMonitor(monitor.(metrics.AccountManagerMonitor)),
			walletaccountmanager.WithValidatorsManager(validatorsManager),
			walletaccountmanager.WithAccountPaths(viper.GetStringSlice("accountmanager.wallet.accounts")),
			walletaccountmanager.WithPassphrases(passphrases),
			walletaccountmanager.WithLocations(viper.GetStringSlice("accountmanager.wallet.locations")),
			walletaccountmanager.WithSlotsPerEpochProvider(eth2Client.(eth2client.SlotsPerEpochProvider)),
			walletaccountmanager.WithFarFutureEpochProvider(eth2Client.(eth2client.FarFutureEpochProvider)),
			walletaccountmanager.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
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
			bestattestationdatastrategy.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			bestattestationdatastrategy.WithLogLevel(logLevel(viper.GetString("strategies.attestationdata.log-level"))),
			bestattestationdatastrategy.WithAttestationDataProviders(attestationDataProviders),
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
			firstattestationdatastrategy.WithLogLevel(logLevel(viper.GetString("strategies.attestationdata.log-level"))),
			firstattestationdatastrategy.WithAttestationDataProviders(attestationDataProviders),
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
			bestbeaconblockproposalstrategy.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			bestbeaconblockproposalstrategy.WithLogLevel(logLevel(viper.GetString("strategies.beaconblockproposal.log-level"))),
			bestbeaconblockproposalstrategy.WithBeaconBlockProposalProviders(beaconBlockProposalProviders),
			bestbeaconblockproposalstrategy.WithSignedBeaconBlockProvider(eth2Client.(eth2client.SignedBeaconBlockProvider)),
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
		for _, address := range viper.GetStringSlice("submitter.beacon-node-addresses") {
			client, err := fetchClient(ctx, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for submitter strategy", address))
			}
			beaconBlockSubmitters[address] = client.(eth2client.BeaconBlockSubmitter)
			attestationsSubmitters[address] = client.(eth2client.AttestationsSubmitter)
			aggregateAttestationSubmitters[address] = client.(eth2client.AggregateAttestationsSubmitter)
			beaconCommitteeSubscriptionsSubmitters[address] = client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)
		}
		submitter, err = multinodesubmitter.New(ctx,
			multinodesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			multinodesubmitter.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
			multinodesubmitter.WithLogLevel(logLevel(viper.GetString("submitter.log-level"))),
			multinodesubmitter.WithBeaconBlockSubmitters(beaconBlockSubmitters),
			multinodesubmitter.WithAttestationsSubmitters(attestationsSubmitters),
			multinodesubmitter.WithAggregateAttestationsSubmitters(aggregateAttestationSubmitters),
			multinodesubmitter.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
		)
	default:
		log.Info().Msg("Starting standard submitter strategy")
		submitter, err = immediatesubmitter.New(ctx,
			immediatesubmitter.WithLogLevel(logLevel(viper.GetString("submitter.log-level"))),
			immediatesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			immediatesubmitter.WithBeaconBlockSubmitter(eth2Client.(eth2client.BeaconBlockSubmitter)),
			immediatesubmitter.WithAttestationsSubmitter(eth2Client.(eth2client.AttestationsSubmitter)),
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
