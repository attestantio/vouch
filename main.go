// Copyright © 2020 - 2023 Attestant Limited.
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

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	dirkaccountmanager "github.com/attestantio/vouch/services/accountmanager/dirk"
	walletaccountmanager "github.com/attestantio/vouch/services/accountmanager/wallet"
	"github.com/attestantio/vouch/services/attestationaggregator"
	standardattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/standard"
	"github.com/attestantio/vouch/services/attester"
	standardattester "github.com/attestantio/vouch/services/attester/standard"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	standardbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/standard"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	standardbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/standard"
	"github.com/attestantio/vouch/services/blockrelay"
	standardblockrelay "github.com/attestantio/vouch/services/blockrelay/standard"
	"github.com/attestantio/vouch/services/cache"
	standardcache "github.com/attestantio/vouch/services/cache/standard"
	"github.com/attestantio/vouch/services/chaintime"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	standardcontroller "github.com/attestantio/vouch/services/controller/standard"
	"github.com/attestantio/vouch/services/graffitiprovider"
	dynamicgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/dynamic"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/services/proposalpreparer"
	standardproposalpreparer "github.com/attestantio/vouch/services/proposalpreparer/standard"
	"github.com/attestantio/vouch/services/scheduler"
	advancedscheduler "github.com/attestantio/vouch/services/scheduler/advanced"
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
	firstbeaconblockrootstrategy "github.com/attestantio/vouch/strategies/beaconblockroot/first"
	majoritybeaconblockrootstrategy "github.com/attestantio/vouch/strategies/beaconblockroot/majority"
	bestblindedbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/blindedbeaconblockproposal/best"
	firstblindedbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/blindedbeaconblockproposal/first"
	"github.com/attestantio/vouch/strategies/builderbid"
	bestbuilderbidstrategy "github.com/attestantio/vouch/strategies/builderbid/best"
	bestsynccommitteecontributionstrategy "github.com/attestantio/vouch/strategies/synccommitteecontribution/best"
	firstsynccommitteecontributionstrategy "github.com/attestantio/vouch/strategies/synccommitteecontribution/first"
	"github.com/attestantio/vouch/util"
	"github.com/aws/aws-sdk-go/aws/credentials"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	majordomo "github.com/wealdtech/go-majordomo"
	asmconfidant "github.com/wealdtech/go-majordomo/confidants/asm"
	directconfidant "github.com/wealdtech/go-majordomo/confidants/direct"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	gsmconfidant "github.com/wealdtech/go-majordomo/confidants/gsm"
	httpconfidant "github.com/wealdtech/go-majordomo/confidants/http"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

// ReleaseVersion is the release version for the code.
var ReleaseVersion = "1.8.0-dev"

func main() {
	exitCode := main2()
	if exitCode != 0 {
		// Exit immediately.
		os.Exit(exitCode)
	}
	// Leave without an explicit exit; this allows cancelled contexts to tidy themselves up.
}

func main2() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fetchConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch configuration: %v\n", err)
		return 1
	}

	majordomo, err := initMajordomo(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise majordomo: %v\n", err)
		return 1
	}

	if exit := runCommands(ctx, majordomo); exit {
		return 0
	}

	if err := initLogging(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logging: %v\n", err)
		return 1
	}

	logModules()
	log.Info().Str("version", ReleaseVersion).Str("commit_hash", util.CommitHash()).Msg("Starting vouch")

	initProfiling()

	if err := initTracing(ctx, majordomo); err != nil {
		log.Error().Err(err).Msg("Failed to initialise tracing")
		return 1
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 8)

	if err := e2types.InitBLS(); err != nil {
		log.Error().Err(err).Msg("Failed to initialise BLS library")
		return 1
	}

	chainTime, controller, err := startServices(ctx, majordomo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise services")
		return 1
	}
	setReady(true)
	log.Info().Msg("All services operational")

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sigCh
	// Received a signal to stop, but don't do so until we have finished attesting for this slot.
	slot := chainTime.CurrentSlot()
	first := true
	for {
		if !controller.HasPendingAttestations(ctx, slot) {
			log.Info().Uint64("slot", uint64(slot)).Msg("Attestations complete; shutting down")
			break
		}
		if first {
			log.Info().Uint64("slot", uint64(slot)).Msg("Waiting for attestations to complete")
			first = false
		}
		time.Sleep(100 * time.Millisecond)
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
	pflag.String("beacon-node-address", "", "Address on which to contact the beacon node")
	pflag.Bool("version", false, "show Vouch version and exit")
	pflag.String("proposer-config-check", "", "show the proposer configuration for the given public key and exit")
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
	viper.SetDefault("timeout", 2*time.Second)
	viper.SetDefault("eth2client.timeout", 2*time.Minute)
	viper.SetDefault("controller.max-proposal-delay", 0)
	viper.SetDefault("controller.max-attestation-delay", 4*time.Second)
	viper.SetDefault("controller.max-sync-committee-message-delay", 4*time.Second)
	viper.SetDefault("controller.attestation-aggregation-delay", 8*time.Second)
	viper.SetDefault("controller.sync-committee-aggregation-delay", 8*time.Second)
	viper.SetDefault("blockrelay.timeout", 1*time.Second)
	viper.SetDefault("blockrelay.listen-address", "0.0.0.0:18550")
	viper.SetDefault("blockrelay.fallback-gas-limit", uint64(30000000))
	viper.SetDefault("accountmanager.dirk.timeout", 30*time.Second)
	viper.SetDefault("strategies.beaconblockproposal.best.execution-payload-factor", float64(0.000005))

	if err := viper.ReadInConfig(); err != nil {
		switch {
		case errors.As(err, &viper.ConfigFileNotFoundError{}):
			// It is allowable for Vouch to not have a configuration file, but only if
			// we have the information from elsewhere (e.g. environment variables).  Check
			// to see if we have any beacon nodes configured, as if not we aren't going to
			// get very far anyway.
			if util.BeaconNodeAddresses("") == nil {
				// Assume the underlying issue is that the configuration file is missing.
				return errors.Wrap(err, "could not find the configuration file")
			}
		case errors.As(err, &viper.ConfigParseError{}):
			return errors.Wrap(err, "could not parse the configuration file")
		default:
			return errors.Wrap(err, "failed to obtain configuration")
		}
	}

	return nil
}

// initProfiling initialises the profiling server.
func initProfiling() {
	profileAddress := viper.GetString("profile-address")
	if profileAddress != "" {
		go func() {
			log.Info().Str("profile_address", profileAddress).Msg("Starting profile server")
			server := &http.Server{
				Addr:              profileAddress,
				ReadHeaderTimeout: 5 * time.Second,
			}
			runtime.SetMutexProfileFraction(1)
			if err := server.ListenAndServe(); err != nil {
				log.Warn().Str("profile_address", profileAddress).Err(err).Msg("Failed to run profile server")
			}
		}()
	}
}

func startClient(ctx context.Context, monitor metrics.Service) (eth2client.Service, error) {
	log.Trace().Msg("Starting consensus client service")
	var consensusClient eth2client.Service
	var err error
	if len(viper.GetStringSlice("beacon-node-addresses")) > 0 {
		consensusClient, err = fetchMultiClient(ctx, monitor, viper.GetStringSlice("beacon-node-addresses"))
	} else {
		consensusClient, err = fetchClient(ctx, monitor, viper.GetString("beacon-node-address"))
	}
	if err != nil {
		return nil, err
	}

	return consensusClient, nil
}

func startServices(ctx context.Context,
	majordomo majordomo.Service,
) (
	chaintime.Service,
	*standardcontroller.Service,
	error,
) {
	eth2Client, chainTime, monitor, err := startBasicServices(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Some beacon nodes do not respond pre-genesis, so we must wait for genesis before proceeding.
	genesisTime := chainTime.GenesisTime()
	now := time.Now()
	waitedForGenesis := false
	if now.Before(genesisTime) {
		waitedForGenesis = true
		// Wait for genesis (or signal, or context cancel).
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
		log.Info().Str("genesis", fmt.Sprintf("%v", genesisTime)).Msg("Waiting for genesis")
		ctx, cancel := context.WithDeadline(ctx, genesisTime)
		defer cancel()
		select {
		case <-sigCh:
			return nil, nil, errors.New("signal received")
		case <-ctx.Done():
			//nolint:errorlint
			switch ctx.Err() {
			case context.DeadlineExceeded:
				log.Info().Msg("Genesis time")
			case context.Canceled:
				return nil, nil, errors.New("context cancelled")
			}
		}
	}

	altairCapable, bellatrixCapable, _, err := consensusClientCapabilities(ctx, eth2Client)
	if err != nil {
		return nil, nil, err
	}

	scheduler, cacheSvc, signerSvc, accountManager, err := startSharedServices(ctx, eth2Client, majordomo, chainTime, monitor)
	if err != nil {
		return nil, nil, err
	}

	submitter, err := selectSubmitterStrategy(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to select submitter")
	}

	blockRelay, err := startBlockRelay(ctx, majordomo, monitor, eth2Client, scheduler, chainTime, accountManager, signerSvc)
	if err != nil {
		return nil, nil, err
	}

	beaconBlockProposer, attester, attestationAggregator, beaconCommitteeSubscriber, err := startSigningServices(ctx, majordomo, monitor, eth2Client, chainTime, cacheSvc, signerSvc, blockRelay, accountManager, submitter)
	if err != nil {
		return nil, nil, err
	}

	var syncCommitteeSubscriber synccommitteesubscriber.Service
	var syncCommitteeMessenger synccommitteemessenger.Service
	var syncCommitteeAggregator synccommitteeaggregator.Service
	if altairCapable {
		syncCommitteeSubscriber, syncCommitteeMessenger, syncCommitteeAggregator, err = startAltairServices(ctx, monitor, eth2Client, submitter, signerSvc, accountManager, chainTime, cacheSvc)
		if err != nil {
			return nil, nil, err
		}
	}

	var proposalPreparer proposalpreparer.Service
	if bellatrixCapable {
		log.Trace().Msg("Starting proposals preparer")
		proposalPreparer, err = standardproposalpreparer.New(ctx,
			standardproposalpreparer.WithLogLevel(util.LogLevel("proposalspreparor")),
			standardproposalpreparer.WithMonitor(monitor),
			standardproposalpreparer.WithChainTimeService(chainTime),
			standardproposalpreparer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
			standardproposalpreparer.WithProposalPreparationsSubmitter(submitter.(eth2client.ProposalPreparationsSubmitter)),
			standardproposalpreparer.WithExecutionConfigProvider(blockRelay.(blockrelay.ExecutionConfigProvider)),
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to start proposal preparer service")
		}
	}

	// The events provider for the controller should only use beacon nodes that are used for attestation data.
	var eventsBeaconNodeAddresses []string
	switch {
	case viper.Get("strategies.attestationdata.best") != nil:
		eventsBeaconNodeAddresses = util.BeaconNodeAddresses("strategies.attestationdata.best")
	case viper.Get("strategies.attestationdata.first") != nil:
		eventsBeaconNodeAddresses = util.BeaconNodeAddresses("strategies.attestationdata.first")
	default:
		eventsBeaconNodeAddresses = util.BeaconNodeAddresses("strategies.attestationdata")
	}
	eventsConsensusClient, err := fetchMultiClient(ctx, monitor, eventsBeaconNodeAddresses)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to fetch multiclient for controller")
	}

	log.Trace().Msg("Starting controller")
	controller, err := standardcontroller.New(ctx,
		standardcontroller.WithLogLevel(util.LogLevel("controller")),
		standardcontroller.WithMonitor(monitor.(metrics.ControllerMonitor)),
		standardcontroller.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardcontroller.WithChainTimeService(chainTime),
		standardcontroller.WithWaitedForGenesis(waitedForGenesis),
		standardcontroller.WithProposerDutiesProvider(eth2Client.(eth2client.ProposerDutiesProvider)),
		standardcontroller.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardcontroller.WithSyncCommitteeDutiesProvider(eth2Client.(eth2client.SyncCommitteeDutiesProvider)),
		standardcontroller.WithEventsProvider(eventsConsensusClient.(eth2client.EventsProvider)),
		standardcontroller.WithScheduler(scheduler),
		standardcontroller.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardcontroller.WithAttester(attester),
		standardcontroller.WithSyncCommitteeMessenger(syncCommitteeMessenger),
		standardcontroller.WithSyncCommitteeAggregator(syncCommitteeAggregator),
		standardcontroller.WithBeaconBlockProposer(beaconBlockProposer),
		standardcontroller.WithBeaconBlockHeadersProvider(eth2Client.(eth2client.BeaconBlockHeadersProvider)),
		standardcontroller.WithSignedBeaconBlockProvider(eth2Client.(eth2client.SignedBeaconBlockProvider)),
		standardcontroller.WithProposalsPreparer(proposalPreparer),
		standardcontroller.WithAttestationAggregator(attestationAggregator),
		standardcontroller.WithBeaconCommitteeSubscriber(beaconCommitteeSubscriber),
		standardcontroller.WithSyncCommitteeSubscriber(syncCommitteeSubscriber),
		standardcontroller.WithAccountsRefresher(accountManager.(accountmanager.Refresher)),
		standardcontroller.WithBlockToSlotSetter(cacheSvc.(cache.BlockRootToSlotSetter)),
		standardcontroller.WithMaxProposalDelay(viper.GetDuration("controller.max-proposal-delay")),
		standardcontroller.WithMaxAttestationDelay(viper.GetDuration("controller.max-attestation-delay")),
		standardcontroller.WithAttestationAggregationDelay(viper.GetDuration("controller.attestation-aggregation-delay")),
		standardcontroller.WithMaxSyncCommitteeMessageDelay(viper.GetDuration("controller.max-sync-committee-message-delay")),
		standardcontroller.WithSyncCommitteeAggregationDelay(viper.GetDuration("controller.sync-committee-aggregation-delay")),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to start controller service")
	}

	return chainTime, controller, nil
}

func startBasicServices(ctx context.Context,
) (
	eth2client.Service,
	chaintime.Service,
	metrics.Service,
	error,
) {
	// Initialise monitor without chainTime service and server for now, so the
	// client can provide metrics.
	monitor, err := startMonitor(ctx, nil, false)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start metrics service")
	}

	eth2Client, err := startClient(ctx, monitor)
	if err != nil {
		return nil, nil, nil, err
	}
	log.Trace().Msg("Starting chain time service")
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(util.LogLevel("chaintime")),
		standardchaintime.WithGenesisProvider(eth2Client.(eth2client.GenesisProvider)),
		standardchaintime.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start chain time service")
	}

	log.Trace().Msg("Starting metrics service")
	// Reinitialise monitor with chainTime service and an operational server.
	monitor, err = startMonitor(ctx, chainTime, true)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start metrics service")
	}
	if err := registerMetrics(monitor); err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to register metrics")
	}
	setRelease(ReleaseVersion)
	setReady(false)

	return eth2Client, chainTime, monitor, nil
}

func startSharedServices(ctx context.Context,
	eth2Client eth2client.Service,
	majordomo majordomo.Service,
	chainTime chaintime.Service,
	monitor metrics.Service,
) (
	scheduler.Service,
	cache.Service,
	signer.Service,
	accountmanager.Service,
	error,
) {
	log.Trace().Msg("Selecting scheduler")
	scheduler, err := selectScheduler(ctx, monitor)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to select scheduler")
	}

	log.Trace().Msg("Starting cache")
	cacheSvc, err := startCache(ctx, monitor, chainTime, scheduler, eth2Client)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start cache")
	}

	log.Trace().Msg("Starting validators manager")
	validatorsManager, err := startValidatorsManager(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start validators manager")
	}

	log.Trace().Msg("Starting signer")
	signerSvc, err := startSigner(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start signer")
	}

	log.Trace().Msg("Starting account manager")
	accountManager, err := startAccountManager(ctx, monitor, eth2Client, validatorsManager, majordomo, chainTime)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start account manager")
	}

	return scheduler, cacheSvc, signerSvc, accountManager, nil
}

func startProviders(ctx context.Context,
	majordomo majordomo.Service,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
	cache cache.Service,
) (
	graffitiprovider.Service,
	eth2client.ProposalProvider,
	eth2client.BlindedProposalProvider,
	eth2client.AttestationDataProvider,
	eth2client.AggregateAttestationProvider,
	error,
) {
	log.Trace().Msg("Starting graffiti provider")
	graffitiProvider, err := startGraffitiProvider(ctx, majordomo)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Wrap(err, "failed to start graffiti provider")
	}

	log.Trace().Msg("Selecting beacon block proposal provider")
	beaconBlockProposalProvider, err := selectProposalProvider(ctx, monitor, eth2Client, chainTime, cache)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Wrap(err, "failed to select beacon block proposal provider")
	}

	log.Trace().Msg("Selecting blinded beacon block proposal provider")
	blindedProposalProvider, err := selectBlindedProposalProvider(ctx, monitor, eth2Client, chainTime, cache)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Wrap(err, "failed to select blinded beacon block proposal provider")
	}

	log.Trace().Msg("Selecting attestation data provider")
	attestationDataProvider, err := selectAttestationDataProvider(ctx, monitor, eth2Client, chainTime, cache)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Wrap(err, "failed to select attestation data provider")
	}

	log.Trace().Msg("Selecting aggregate attestation provider")
	aggregateAttestationProvider, err := selectAggregateAttestationProvider(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Wrap(err, "failed to select aggregate attestation provider")
	}

	return graffitiProvider, beaconBlockProposalProvider, blindedProposalProvider, attestationDataProvider, aggregateAttestationProvider, nil
}

func startAltairServices(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	submitterStrategy submitter.Service,
	signerSvc signer.Service,
	accountManager accountmanager.Service,
	chainTime chaintime.Service,
	cacheSvc cache.Service,
) (
	synccommitteesubscriber.Service,
	synccommitteemessenger.Service,
	synccommitteeaggregator.Service,
	error,
) {
	log.Trace().Msg("Starting sync committee subscriber service")
	syncCommitteeSubscriber, err := standardsynccommitteesubscriber.New(ctx,
		standardsynccommitteesubscriber.WithLogLevel(util.LogLevel("synccommiteesubscriber")),
		standardsynccommitteesubscriber.WithMonitor(monitor.(metrics.SyncCommitteeSubscriptionMonitor)),
		standardsynccommitteesubscriber.WithSyncCommitteeSubmitter(submitterStrategy.(submitter.SyncCommitteeSubscriptionsSubmitter)),
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start beacon committee subscriber service")
	}

	log.Trace().Msg("Selecting sync committee contribution provider")
	syncCommitteeContributionProvider, err := selectSyncCommitteeContributionProvider(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to select sync committee contribution provider")
	}

	log.Trace().Msg("Selecting beacon block root provider")
	beaconBlockRootProvider, err := selectBeaconBlockRootProvider(ctx, monitor, eth2Client, cacheSvc)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to select beacon block root provider")
	}

	log.Trace().Msg("Starting sync committee aggregator")
	syncCommitteeAggregator, err := standardsynccommitteeaggregator.New(ctx,
		standardsynccommitteeaggregator.WithLogLevel(util.LogLevel("synccommitteeaggregator")),
		standardsynccommitteeaggregator.WithMonitor(monitor.(metrics.SyncCommitteeAggregationMonitor)),
		standardsynccommitteeaggregator.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardsynccommitteeaggregator.WithBeaconBlockRootProvider(beaconBlockRootProvider),
		standardsynccommitteeaggregator.WithContributionAndProofSigner(signerSvc.(signer.ContributionAndProofSigner)),
		standardsynccommitteeaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardsynccommitteeaggregator.WithSyncCommitteeContributionProvider(syncCommitteeContributionProvider),
		standardsynccommitteeaggregator.WithSyncCommitteeContributionsSubmitter(submitterStrategy.(submitter.SyncCommitteeContributionsSubmitter)),
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start sync committee aggregator service")
	}

	log.Trace().Msg("Starting sync committee messenger")
	syncCommitteeMessenger, err := standardsynccommitteemessenger.New(ctx,
		standardsynccommitteemessenger.WithLogLevel(util.LogLevel("synccommitteemessenger")),
		standardsynccommitteemessenger.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
		standardsynccommitteemessenger.WithMonitor(monitor.(metrics.SyncCommitteeMessageMonitor)),
		standardsynccommitteemessenger.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardsynccommitteemessenger.WithChainTimeService(chainTime),
		standardsynccommitteemessenger.WithSyncCommitteeAggregator(syncCommitteeAggregator),
		standardsynccommitteemessenger.WithBeaconBlockRootProvider(beaconBlockRootProvider),
		standardsynccommitteemessenger.WithSyncCommitteeMessagesSubmitter(submitterStrategy.(submitter.SyncCommitteeMessagesSubmitter)),
		standardsynccommitteemessenger.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardsynccommitteemessenger.WithSyncCommitteeRootSigner(signerSvc.(signer.SyncCommitteeRootSigner)),
		standardsynccommitteemessenger.WithSyncCommitteeSelectionSigner(signerSvc.(signer.SyncCommitteeSelectionSigner)),
		standardsynccommitteemessenger.WithSyncCommitteeSubscriptionsSubmitter(submitterStrategy.(submitter.SyncCommitteeSubscriptionsSubmitter)),
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start sync committee messenger service")
	}

	return syncCommitteeSubscriber, syncCommitteeMessenger, syncCommitteeAggregator, nil
}

func startSigningServices(ctx context.Context,
	majordomo majordomo.Service,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
	cacheSvc cache.Service,
	signerSvc signer.Service,
	blockRelay blockrelay.Service,
	accountManager accountmanager.Service,
	submitterStrategy submitter.Service,
) (
	beaconblockproposer.Service,
	attester.Service,
	attestationaggregator.Service,
	beaconcommitteesubscriber.Service,
	error,
) {
	graffitiProvider, proposalProvider, blindedProposalProvider, attestationDataProvider, aggregateAttestationProvider, err := startProviders(ctx, majordomo, monitor, eth2Client, chainTime, cacheSvc)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	beaconBlockProposer, err := standardbeaconblockproposer.New(ctx,
		standardbeaconblockproposer.WithLogLevel(util.LogLevel("beaconblockproposer")),
		standardbeaconblockproposer.WithChainTime(chainTime),
		standardbeaconblockproposer.WithProposalDataProvider(proposalProvider),
		standardbeaconblockproposer.WithBlindedProposalDataProvider(blindedProposalProvider),
		standardbeaconblockproposer.WithBlockAuctioneer(blockRelay.(blockauctioneer.BlockAuctioneer)),
		standardbeaconblockproposer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardbeaconblockproposer.WithExecutionChainHeadProvider(cacheSvc.(cache.ExecutionChainHeadProvider)),
		standardbeaconblockproposer.WithGraffitiProvider(graffitiProvider),
		standardbeaconblockproposer.WithMonitor(monitor),
		standardbeaconblockproposer.WithProposalSubmitter(submitterStrategy.(submitter.ProposalSubmitter)),
		standardbeaconblockproposer.WithRANDAORevealSigner(signerSvc.(signer.RANDAORevealSigner)),
		standardbeaconblockproposer.WithBeaconBlockSigner(signerSvc.(signer.BeaconBlockSigner)),
		standardbeaconblockproposer.WithBlobSidecarSigner(signerSvc.(signer.BlobSidecarSigner)),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start beacon block proposer service")
	}

	log.Trace().Msg("Starting attester")
	attester, err := standardattester.New(ctx,
		standardattester.WithLogLevel(util.LogLevel("attester")),
		standardattester.WithProcessConcurrency(util.ProcessConcurrency("attester")),
		standardattester.WithChainTimeService(chainTime),
		standardattester.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardattester.WithAttestationDataProvider(attestationDataProvider),
		standardattester.WithAttestationsSubmitter(submitterStrategy.(submitter.AttestationsSubmitter)),
		standardattester.WithMonitor(monitor.(metrics.AttestationMonitor)),
		standardattester.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardattester.WithBeaconAttestationsSigner(signerSvc.(signer.BeaconAttestationsSigner)),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start attester service")
	}

	log.Trace().Msg("Starting beacon attestation aggregator")
	attestationAggregator, err := standardattestationaggregator.New(ctx,
		standardattestationaggregator.WithLogLevel(util.LogLevel("attestationaggregator")),
		standardattestationaggregator.WithAggregateAttestationProvider(aggregateAttestationProvider),
		standardattestationaggregator.WithAggregateAttestationsSubmitter(submitterStrategy.(submitter.AggregateAttestationsSubmitter)),
		standardattestationaggregator.WithMonitor(monitor.(metrics.AttestationAggregationMonitor)),
		standardattestationaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardattestationaggregator.WithSlotSelectionSigner(signerSvc.(signer.SlotSelectionSigner)),
		standardattestationaggregator.WithAggregateAndProofSigner(signerSvc.(signer.AggregateAndProofSigner)),
		standardattestationaggregator.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start beacon attestation aggregator service")
	}

	log.Trace().Msg("Starting beacon committee subscriber service")
	beaconCommitteeSubscriber, err := standardbeaconcommitteesubscriber.New(ctx,
		standardbeaconcommitteesubscriber.WithLogLevel(util.LogLevel("beaconcommiteesubscriber")),
		standardbeaconcommitteesubscriber.WithProcessConcurrency(util.ProcessConcurrency("beaconcommitteesubscriber")),
		standardbeaconcommitteesubscriber.WithMonitor(monitor.(metrics.BeaconCommitteeSubscriptionMonitor)),
		standardbeaconcommitteesubscriber.WithChainTimeService(chainTime),
		standardbeaconcommitteesubscriber.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardbeaconcommitteesubscriber.WithAttestationAggregator(attestationAggregator),
		standardbeaconcommitteesubscriber.WithBeaconCommitteeSubmitter(submitterStrategy.(submitter.BeaconCommitteeSubscriptionsSubmitter)),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start beacon committee subscriber service")
	}

	return beaconBlockProposer, attester, attestationAggregator, beaconCommitteeSubscriber, nil
}

// logModules logs a list of modules with their versions.
func logModules() {
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		log.Trace().Str("path", buildInfo.Path).Msg("Main package")
		for _, dep := range buildInfo.Deps {
			path := dep.Path
			if dep.Replace != nil {
				path = dep.Replace.Path
			}
			log.Trace().Str("path", path).Str("version", dep.Version).Msg("Dependency")
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

// initMajordomo initialises majordomo and its required confidants given user input.
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

	httpConfidant, err := httpconfidant.New(ctx,
		httpconfidant.WithLogLevel(util.LogLevel("majordomo.confidants.http")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP confidant")
	}
	if err := majordomo.RegisterConfidant(ctx, httpConfidant); err != nil {
		return nil, errors.Wrap(err, "failed to register HTTP confidant")
	}

	return majordomo, nil
}

// startMonitor starts the relevant metrics monitor given user input.
func startMonitor(ctx context.Context,
	chainTime chaintime.Service,
	createServer bool,
) (
	metrics.Service,
	error,
) {
	log.Trace().Msg("Starting metrics service")
	var monitor metrics.Service
	if viper.Get("metrics.prometheus.listen-address") != nil {
		var err error
		monitor, err = prometheusmetrics.New(ctx,
			prometheusmetrics.WithLogLevel(util.LogLevel("metrics.prometheus")),
			prometheusmetrics.WithAddress(viper.GetString("metrics.prometheus.listen-address")),
			prometheusmetrics.WithChainTime(chainTime),
			prometheusmetrics.WithCreateServer(createServer),
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

// selectScheduler selects the appropriate scheduler given user input.
func selectScheduler(ctx context.Context, monitor metrics.Service) (scheduler.Service, error) {
	var scheduler scheduler.Service
	var err error
	switch viper.GetString("scheduler.style") {
	case "basic":
		log.Warn().Msg("Basic scheduler is no longer available; defaulting to advanced scheduler.  To avoid this message in future please change your scheduler type to 'advanced'")
		scheduler, err = advancedscheduler.New(ctx,
			advancedscheduler.WithLogLevel(util.LogLevel("scheduler.advanced")),
			advancedscheduler.WithMonitor(monitor.(metrics.SchedulerMonitor)),
		)
	default:
		log.Info().Msg("Starting advanced scheduler")
		scheduler, err = advancedscheduler.New(ctx,
			advancedscheduler.WithLogLevel(util.LogLevel("scheduler.advanced")),
			advancedscheduler.WithMonitor(monitor.(metrics.SchedulerMonitor)),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start scheduler service")
	}
	return scheduler, nil
}

// startCache starts the relevant cache given user input.
func startCache(ctx context.Context,
	monitor metrics.Service,
	chainTime chaintime.Service,
	scheduler scheduler.Service,
	consensusClient eth2client.Service,
) (cache.Service, error) {
	log.Trace().Msg("Starting cache")
	cache, err := standardcache.New(ctx,
		standardcache.WithLogLevel(util.LogLevel("cache.standard")),
		standardcache.WithMonitor(monitor),
		standardcache.WithScheduler(scheduler),
		standardcache.WithChainTime(chainTime),
		standardcache.WithConsensusClient(consensusClient),
	)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

// startGraffitiProvider starts the appropriate graffiti provider given user input.
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

// startValidatorsManager starts the appropriate validators manager given user input.
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

// startAccountManager starts the appropriate account manager given user input.
func startAccountManager(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service, validatorsManager validatorsmanager.Service, majordomo majordomo.Service, chainTime chaintime.Service) (accountmanager.Service, error) {
	if len(viper.GetStringSlice("accountmanager.dirk.accounts")) > 0 &&
		len(viper.GetStringSlice("accountmanager.wallet.accounts")) > 0 {
		return nil, errors.New("multiple account managers configured; Vouch only supports a single account manager")
	}

	var accountManager accountmanager.Service
	if len(viper.GetStringSlice("accountmanager.dirk.accounts")) > 0 {
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
			dirkaccountmanager.WithTimeout(util.Timeout("accountmanager.dirk")),
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

	if len(viper.GetStringSlice("accountmanager.wallet.accounts")) > 0 {
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
			walletaccountmanager.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
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

// selectAttestationDataProvider selects the appropriate attestation data provider given user input.
func selectAttestationDataProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
	cacheSvc cache.Service,
) (eth2client.AttestationDataProvider, error) {
	var attestationDataProvider eth2client.AttestationDataProvider
	var err error
	switch viper.GetString("strategies.attestationdata.style") {
	case "best":
		log.Info().Msg("Starting best attestation data strategy")
		attestationDataProviders := make(map[string]eth2client.AttestationDataProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.attestationdata.best") {
			client, err := fetchClient(ctx, monitor, address)
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
			bestattestationdatastrategy.WithChainTime(chainTime),
			bestattestationdatastrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best attestation data strategy")
		}
	case "first":
		log.Info().Msg("Starting first attestation data strategy")
		attestationDataProviders := make(map[string]eth2client.AttestationDataProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.attestationdata.first") {
			client, err := fetchClient(ctx, monitor, address)
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

// selectAggregateAttestationProvider selects the appropriate aggregate attestation provider given user input.
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
		for _, address := range util.BeaconNodeAddresses("strategies.aggregateattestation.best") {
			client, err := fetchClient(ctx, monitor, address)
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
		for _, address := range util.BeaconNodeAddresses("strategies.aggregateattestation.first") {
			client, err := fetchClient(ctx, monitor, address)
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

// selectProposalProvider selects the appropriate beacon block proposal provider given user input.
func selectProposalProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
	cacheSvc cache.Service,
) (eth2client.ProposalProvider, error) {
	var proposalProvider eth2client.ProposalProvider
	var err error
	switch viper.GetString("strategies.beaconblockproposal.style") {
	case "best":
		log.Info().Msg("Starting best beacon block proposal strategy")
		proposalProviders := make(map[string]eth2client.ProposalProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.beaconblockproposal.best") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block proposal strategy", address))
			}
			proposalProviders[address] = client.(eth2client.ProposalProvider)
		}
		proposalProvider, err = bestbeaconblockproposalstrategy.New(ctx,
			bestbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestbeaconblockproposalstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.beaconblockproposal.best")),
			bestbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockproposal.best")),
			bestbeaconblockproposalstrategy.WithEventsProvider(eth2Client.(eth2client.EventsProvider)),
			bestbeaconblockproposalstrategy.WithChainTimeService(chainTime),
			bestbeaconblockproposalstrategy.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			bestbeaconblockproposalstrategy.WithProposalProviders(proposalProviders),
			bestbeaconblockproposalstrategy.WithSignedBeaconBlockProvider(eth2Client.(eth2client.SignedBeaconBlockProvider)),
			bestbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.beaconblockproposal.best")),
			bestbeaconblockproposalstrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			bestbeaconblockproposalstrategy.WithExecutionPayloadFactor(viper.GetFloat64("strategies.beaconblockproposal.best.execution-payload-factor")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best beacon block proposal strategy")
		}
	case "first":
		log.Info().Msg("Starting first beacon block proposal strategy")
		proposalProviders := make(map[string]eth2client.ProposalProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.beaconblockproposal.first") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block proposal strategy", address))
			}
			proposalProviders[address] = client.(eth2client.ProposalProvider)
		}
		proposalProvider, err = firstbeaconblockproposalstrategy.New(ctx,
			firstbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockproposal.first")),
			firstbeaconblockproposalstrategy.WithProposalProviders(proposalProviders),
			firstbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.beaconblockproposal.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first beacon block proposal strategy")
		}
	default:
		log.Info().Msg("Starting simple beacon block proposal strategy")
		proposalProvider = eth2Client.(eth2client.ProposalProvider)
	}

	return proposalProvider, nil
}

// selectBlindedProposalProvider selects the appropriate blinded proposal provider given user input.
func selectBlindedProposalProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
	cacheSvc cache.Service,
) (eth2client.BlindedProposalProvider, error) {
	var blindedProposalProvider eth2client.BlindedProposalProvider
	var err error
	switch viper.GetString("strategies.blindedbeaconblockproposal.style") {
	case "best":
		log.Info().Msg("Starting best blinded beacon block proposal strategy")
		blindedProposalProviders := make(map[string]eth2client.BlindedProposalProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.blindedbeaconblockproposal.best") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for blinded beacon block proposal strategy", address))
			}
			blindedProposalProviders[address] = client.(eth2client.BlindedProposalProvider)
		}
		blindedProposalProvider, err = bestblindedbeaconblockproposalstrategy.New(ctx,
			bestblindedbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			bestblindedbeaconblockproposalstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.blindedbeaconblockproposal.best")),
			bestblindedbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.blindedbeaconblockproposal.best")),
			bestblindedbeaconblockproposalstrategy.WithEventsProvider(eth2Client.(eth2client.EventsProvider)),
			bestblindedbeaconblockproposalstrategy.WithChainTimeService(chainTime),
			bestblindedbeaconblockproposalstrategy.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			bestblindedbeaconblockproposalstrategy.WithBlindedProposalProviders(blindedProposalProviders),
			bestblindedbeaconblockproposalstrategy.WithSignedBeaconBlockProvider(eth2Client.(eth2client.SignedBeaconBlockProvider)),
			bestblindedbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.blindedbeaconblockproposal.best")),
			bestblindedbeaconblockproposalstrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best blinded beacon block proposal strategy")
		}
	case "first":
		log.Info().Msg("Starting first blinded beacon block proposal strategy")
		blindedProposalProviders := make(map[string]eth2client.BlindedProposalProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.blindedbeaconblockproposal.first") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for blinded beacon block proposal strategy", address))
			}
			blindedProposalProviders[address] = client.(eth2client.BlindedProposalProvider)
		}
		blindedProposalProvider, err = firstblindedbeaconblockproposalstrategy.New(ctx,
			firstblindedbeaconblockproposalstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstblindedbeaconblockproposalstrategy.WithLogLevel(util.LogLevel("strategies.blindedbeaconblockproposal.first")),
			firstblindedbeaconblockproposalstrategy.WithChainTimeService(chainTime),
			firstblindedbeaconblockproposalstrategy.WithBlindedProposalProviders(blindedProposalProviders),
			firstblindedbeaconblockproposalstrategy.WithTimeout(util.Timeout("strategies.blindedbeaconblockproposal.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first blinded beacon block proposal strategy")
		}
	default:
		log.Info().Msg("Starting simple blinded beacon block proposal strategy")
		blindedProposalProvider = eth2Client.(eth2client.BlindedProposalProvider)
	}

	return blindedProposalProvider, nil
}

// selectSyncCommitteeContributionProvider selects the appropriate sync committee contribution provider given user input.
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
		for _, address := range util.BeaconNodeAddresses("strategies.synccommitteecontribution.best") {
			client, err := fetchClient(ctx, monitor, address)
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
		for _, address := range util.BeaconNodeAddresses("strategies.synccommitteecontribution.first") {
			client, err := fetchClient(ctx, monitor, address)
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

// selectBeaconBlockRootProvider selects the appropriate beacon block root provider given user input.
func selectBeaconBlockRootProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	cacheSvc cache.Service,
) (eth2client.BeaconBlockRootProvider, error) {
	var beaconBlockRootProvider eth2client.BeaconBlockRootProvider
	var err error
	switch viper.GetString("strategies.beaconblockroot.style") {
	case "majority":
		log.Info().Msg("Starting majority beacon block root strategy")
		beaconBlockRootProviders := make(map[string]eth2client.BeaconBlockRootProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.beaconblockroot.majority") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block root strategy", address))
			}
			beaconBlockRootProviders[address] = client.(eth2client.BeaconBlockRootProvider)
		}

		beaconBlockRootProvider, err = majoritybeaconblockrootstrategy.New(ctx,
			majoritybeaconblockrootstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			majoritybeaconblockrootstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.beaconblockroot.best")),
			majoritybeaconblockrootstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockroot.best")),
			majoritybeaconblockrootstrategy.WithBeaconBlockRootProviders(beaconBlockRootProviders),
			majoritybeaconblockrootstrategy.WithTimeout(util.Timeout("strategies.beaconblockroot.best")),
			majoritybeaconblockrootstrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start best sync committee contribution strategy")
		}
	case "first":
		log.Info().Msg("Starting first beacon block root strategy")
		beaconBlockRootProviders := make(map[string]eth2client.BeaconBlockRootProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.beaconblockroot.first") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block root strategy", address))
			}
			beaconBlockRootProviders[address] = client.(eth2client.BeaconBlockRootProvider)
		}
		beaconBlockRootProvider, err = firstbeaconblockrootstrategy.New(ctx,
			firstbeaconblockrootstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstbeaconblockrootstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockroot.first")),
			firstbeaconblockrootstrategy.WithBeaconBlockRootProviders(beaconBlockRootProviders),
			firstbeaconblockrootstrategy.WithTimeout(util.Timeout("strategies.beaconblockroot.first")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start first beacon block root strategy")
		}
	default:
		log.Info().Msg("Starting simple beacon block root strategy")
		beaconBlockRootProvider = eth2Client.(eth2client.BeaconBlockRootProvider)
	}

	return beaconBlockRootProvider, nil
}

// selectSubmitterStrategy selects the appropriate submitter strategy given user input.
func selectSubmitterStrategy(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service) (submitter.Service, error) {
	log.Trace().Msg("Selecting submitter strategy")

	var submitter submitter.Service
	var err error
	switch viper.GetString("submitter.style") {
	case "multinode", "all":
		log.Info().Msg("Starting multinode submitter strategy")
		submitter, err = startMultinodeSubmitter(ctx, monitor)
	default:
		log.Info().Msg("Starting standard submitter strategy")
		submitter, err = immediatesubmitter.New(ctx,
			immediatesubmitter.WithLogLevel(util.LogLevel("submitter.immediate")),
			immediatesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			immediatesubmitter.WithProposalSubmitter(eth2Client.(eth2client.ProposalSubmitter)),
			immediatesubmitter.WithAttestationsSubmitter(eth2Client.(eth2client.AttestationsSubmitter)),
			immediatesubmitter.WithSyncCommitteeMessagesSubmitter(eth2Client.(eth2client.SyncCommitteeMessagesSubmitter)),
			immediatesubmitter.WithSyncCommitteeContributionsSubmitter(eth2Client.(eth2client.SyncCommitteeContributionsSubmitter)),
			immediatesubmitter.WithSyncCommitteeSubscriptionsSubmitter(eth2Client.(eth2client.SyncCommitteeSubscriptionsSubmitter)),
			immediatesubmitter.WithBeaconCommitteeSubscriptionsSubmitter(eth2Client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)),
			immediatesubmitter.WithAggregateAttestationsSubmitter(eth2Client.(eth2client.AggregateAttestationsSubmitter)),
			immediatesubmitter.WithProposalPreparationsSubmitter(eth2Client.(eth2client.ProposalPreparationsSubmitter)),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start submitter service")
	}
	return submitter, nil
}

func startMultinodeSubmitter(ctx context.Context,
	monitor metrics.Service,
) (
	submitter.Service,
	error,
) {
	aggregateAttestationSubmitters := make(map[string]eth2client.AggregateAttestationsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.aggregateattestation.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for aggregate attestation submitter strategy", address))
		}
		aggregateAttestationSubmitters[address] = client.(eth2client.AggregateAttestationsSubmitter)
	}

	attestationsSubmitters := make(map[string]eth2client.AttestationsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.attestation.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for attestation submitter strategy", address))
		}
		attestationsSubmitters[address] = client.(eth2client.AttestationsSubmitter)
	}

	proposalSubmitters := make(map[string]eth2client.ProposalSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.proposal.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for proposal submitter strategy", address))
		}
		proposalSubmitters[address] = client.(eth2client.ProposalSubmitter)
	}

	beaconCommitteeSubscriptionsSubmitters := make(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.beaconcommitteesubscription.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon committee subscription submitter strategy", address))
		}
		beaconCommitteeSubscriptionsSubmitters[address] = client.(eth2client.BeaconCommitteeSubscriptionsSubmitter)
	}

	proposalPreparationSubmitters := make(map[string]eth2client.ProposalPreparationsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.proposalpreparation.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for proposal preparation submitter strategy", address))
		}
		proposalPreparationSubmitters[address] = client.(eth2client.ProposalPreparationsSubmitter)
	}

	syncCommitteeContributionsSubmitters := make(map[string]eth2client.SyncCommitteeContributionsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.synccommitteecontribution.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for sync committee contribution submitter strategy", address))
		}
		syncCommitteeContributionsSubmitters[address] = client.(eth2client.SyncCommitteeContributionsSubmitter)
	}

	syncCommitteeMessagesSubmitters := make(map[string]eth2client.SyncCommitteeMessagesSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.synccommitteemessage.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for sync committee message submitter strategy", address))
		}
		syncCommitteeMessagesSubmitters[address] = client.(eth2client.SyncCommitteeMessagesSubmitter)
	}

	syncCommitteeSubscriptionsSubmitters := make(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter)
	for _, address := range util.BeaconNodeAddresses("submitter.synccommitteesubscription.multinode") {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for sync committee subscription submitter strategy", address))
		}
		syncCommitteeSubscriptionsSubmitters[address] = client.(eth2client.SyncCommitteeSubscriptionsSubmitter)
	}

	submitter, err := multinodesubmitter.New(ctx,
		multinodesubmitter.WithClientMonitor(monitor.(metrics.ClientMonitor)),
		multinodesubmitter.WithProcessConcurrency(util.ProcessConcurrency("submitter.multinode")),
		multinodesubmitter.WithLogLevel(util.LogLevel("submitter.multinode")),
		multinodesubmitter.WithTimeout(util.Timeout("submitter.multinode")),
		multinodesubmitter.WithProposalSubmitters(proposalSubmitters),
		multinodesubmitter.WithAttestationsSubmitters(attestationsSubmitters),
		multinodesubmitter.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
		multinodesubmitter.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
		multinodesubmitter.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
		multinodesubmitter.WithAggregateAttestationsSubmitters(aggregateAttestationSubmitters),
		multinodesubmitter.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
		multinodesubmitter.WithProposalPreparationsSubmitters(proposalPreparationSubmitters),
	)
	if err != nil {
		return nil, err
	}

	return submitter, nil
}

// runCommands potentially runs commands.
// Returns true if Vouch should exit.
func runCommands(ctx context.Context,
	majordomo majordomo.Service,
) bool {
	if viper.GetBool("version") {
		fmt.Printf("%s\n", ReleaseVersion)
		return true
	}

	if viper.GetString("proposer-config-check") != "" {
		return proposerConfigCheck(ctx, majordomo)
	}

	return false
}

func consensusClientCapabilities(ctx context.Context, consensusClient eth2client.Service) (bool, bool, bool, error) {
	// Decide if the ETH2 client is capable of Altair.
	altairCapable := false
	specResponse, err := consensusClient.(eth2client.SpecProvider).Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return false, false, false, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data
	if _, exists := spec["ALTAIR_FORK_EPOCH"]; exists {
		altairCapable = true
		log.Info().Msg("Client is Altair-capable")
	} else {
		log.Info().Msg("Client is not Altair-capable")
	}

	// Decide if the ETH2 client is capabale of Bellatrix.
	bellatrixCapable := false
	if _, exists := spec["BELLATRIX_FORK_EPOCH"]; exists {
		bellatrixCapable = true
		log.Info().Msg("Client is Bellatrix-capable")
	} else {
		log.Info().Msg("Client is not Bellatrix-capable")
	}

	// Decide if the ETH2 client is capabale of Capella.
	capellaCapable := false
	if _, exists := spec["CAPELLA_FORK_EPOCH"]; exists {
		capellaCapable = true
		log.Info().Msg("Client is Capella-capable")
	} else {
		log.Info().Msg("Client is not Capella-capable")
	}

	return altairCapable, bellatrixCapable, capellaCapable, nil
}

func startBlockRelay(ctx context.Context,
	majordomo majordomo.Service,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	scheduler scheduler.Service,
	chainTime chaintime.Service,
	accountManager accountmanager.Service,
	signerSvc signer.Service,
) (
	blockrelay.Service,
	error,
) {
	builderBidProvider, err := selectBuilderBidProvider(ctx, monitor, eth2Client, chainTime)
	if err != nil {
		return nil, err
	}

	// We also need to submit validator registrations to all nodes that are acting as blinded beacon block proposers, as
	// some of them use the registration as part of the condition to decide if the blinded block should be called or not.
	bestBeaconNodeAddresses := util.BeaconNodeAddresses("strategies.blindedbeaconblockproposal.best")
	firstBeaconNodeAddresses := util.BeaconNodeAddresses("strategies.blindedbeaconblockproposal.first")
	secondaryValidatorRegistrationsSubmitters := make([]eth2client.ValidatorRegistrationsSubmitter, 0, len(bestBeaconNodeAddresses)+len(firstBeaconNodeAddresses))
	clients := make(map[string]struct{})
	for _, address := range bestBeaconNodeAddresses {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for blinded beacon block proposal strategy", address))
		}
		secondaryValidatorRegistrationsSubmitters = append(secondaryValidatorRegistrationsSubmitters, client.(eth2client.ValidatorRegistrationsSubmitter))
		clients[address] = struct{}{}
	}
	for _, address := range firstBeaconNodeAddresses {
		if _, exists := clients[address]; !exists {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for blinded beacon block proposal strategy", address))
			}
			secondaryValidatorRegistrationsSubmitters = append(secondaryValidatorRegistrationsSubmitters, client.(eth2client.ValidatorRegistrationsSubmitter))
			clients[address] = struct{}{}
		}
	}

	var fallbackFeeRecipient bellatrix.ExecutionAddress
	feeRecipient, err := hex.DecodeString(strings.TrimPrefix(viper.GetString("blockrelay.fallback-fee-recipient"), "0x"))
	if err != nil {
		return nil, errors.New("blockrelay: invalid fallback fee recipient")
	}
	if len(feeRecipient) == 0 {
		return nil, errors.New("blockrelay: no fallback fee recipient supplied")
	}
	if len(feeRecipient) != len(fallbackFeeRecipient) {
		return nil, errors.New("blockrelay: incorrect length for fallback fee recipient")
	}
	copy(fallbackFeeRecipient[:], feeRecipient)

	excludedBuilders := make([]phase0.BLSPubKey, len(viper.GetStringSlice("blockrelay.excluded-builders")))
	for i, excludedBuilder := range viper.GetStringSlice("blockrelay.excluded-builders") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(excludedBuilder, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode excluded builder")
		}
		if len(tmp) != phase0.PublicKeyLength {
			return nil, errors.New("incorrect length for excluded builder")
		}
		copy(excludedBuilders[i][:], tmp)
	}

	var blockRelay blockrelay.Service
	blockRelay, err = standardblockrelay.New(ctx,
		standardblockrelay.WithLogLevel(util.LogLevel("blockrelay")),
		standardblockrelay.WithMonitor(monitor),
		standardblockrelay.WithMajordomo(majordomo),
		standardblockrelay.WithScheduler(scheduler),
		standardblockrelay.WithChainTime(chainTime),
		standardblockrelay.WithConfigURL(viper.GetString("blockrelay.config.url")),
		standardblockrelay.WithFallbackFeeRecipient(fallbackFeeRecipient),
		standardblockrelay.WithFallbackGasLimit(viper.GetUint64("blockrelay.fallback-gas-limit")),
		standardblockrelay.WithClientCertURL(viper.GetString("blockrelay.config.client-cert")),
		standardblockrelay.WithClientKeyURL(viper.GetString("blockrelay.config.client-key")),
		standardblockrelay.WithCACertURL(viper.GetString("blockrelay.config.ca-cert")),
		standardblockrelay.WithAccountsProvider(accountManager.(accountmanager.AccountsProvider)),
		standardblockrelay.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardblockrelay.WithListenAddress(viper.GetString("blockrelay.listen-address")),
		standardblockrelay.WithValidatorRegistrationSigner(signerSvc.(signer.ValidatorRegistrationSigner)),
		standardblockrelay.WithSecondaryValidatorRegistrationsSubmitters(secondaryValidatorRegistrationsSubmitters),
		standardblockrelay.WithLogResults(viper.GetBool("blockrelay.log-results")),
		standardblockrelay.WithReleaseVersion(ReleaseVersion),
		standardblockrelay.WithBuilderBidProvider(builderBidProvider),
		standardblockrelay.WithExcludedBuilders(excludedBuilders),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to start block relay")
	}

	return blockRelay, nil
}

// selectBuilderBidProvider selects the provider for builder bids.
// Builder bids are blinded execution payload headers provided by relays.
func selectBuilderBidProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	chainTime chaintime.Service,
) (
	builderbid.Provider,
	error,
) {
	log.Trace().Msg("Selecting builder bid strategy")

	var provider builderbid.Provider
	var err error

	switch viper.GetString("strategies.builderbid.style") {
	case "best", "":
		log.Info().Msg("Starting best builder bid strategy")
		provider, err = bestbuilderbidstrategy.New(ctx,
			bestbuilderbidstrategy.WithLogLevel(util.LogLevel("strategies.builderbid.best")),
			bestbuilderbidstrategy.WithMonitor(monitor),
			bestbuilderbidstrategy.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			bestbuilderbidstrategy.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
			bestbuilderbidstrategy.WithChainTime(chainTime),
			bestbuilderbidstrategy.WithTimeout(util.Timeout("strategies.builderbid.best")),
			bestbuilderbidstrategy.WithReleaseVersion(ReleaseVersion),
		)
	default:
		err = fmt.Errorf("unknown builder bid strategy %s", viper.GetString("strategies.builderbid.style"))
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate builder bid strategy")
	}

	return provider, nil
}
