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

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
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
	"github.com/attestantio/vouch/services/multiinstance"
	alwaysmultiinstance "github.com/attestantio/vouch/services/multiinstance/always"
	staticdelaymultiinstance "github.com/attestantio/vouch/services/multiinstance/staticdelay"
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
	majorityattestationdatastrategy "github.com/attestantio/vouch/strategies/attestationdata/majority"
	combinedattestationpoolstrategy "github.com/attestantio/vouch/strategies/attestationpool/combined"
	firstbeaconblockheaderstrategy "github.com/attestantio/vouch/strategies/beaconblockheader/first"
	bestbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	firstbeaconblockproposalstrategy "github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	firstbeaconblockrootstrategy "github.com/attestantio/vouch/strategies/beaconblockroot/first"
	latestbeaconblockrootstrategy "github.com/attestantio/vouch/strategies/beaconblockroot/latest"
	majoritybeaconblockrootstrategy "github.com/attestantio/vouch/strategies/beaconblockroot/majority"
	"github.com/attestantio/vouch/strategies/builderbid"
	bestbuilderbidstrategy "github.com/attestantio/vouch/strategies/builderbid/best"
	deadlinebuilderbidstrategy "github.com/attestantio/vouch/strategies/builderbid/deadline"
	firstsignedbeaconblockstrategy "github.com/attestantio/vouch/strategies/signedbeaconblock/first"
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
var ReleaseVersion = "1.11.0-fulu.1"

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

	if runCommands(ctx, majordomo) {
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
	viper.SetDefault("logging.timestamp.format", "2006-01-02T15:04:05.000Z07:00")
	viper.SetDefault("process-concurrency", int64(runtime.GOMAXPROCS(-1)))
	viper.SetDefault("timeout", 2*time.Second)
	viper.SetDefault("eth2client.timeout", 2*time.Minute)
	viper.SetDefault("eth2client.allow-delayed-start", true)
	viper.SetDefault("controller.max-proposal-delay", 0)
	viper.SetDefault("controller.max-attestation-delay", 4*time.Second)
	viper.SetDefault("controller.max-sync-committee-message-delay", 4*time.Second)
	viper.SetDefault("controller.attestation-aggregation-delay", 8*time.Second)
	viper.SetDefault("controller.sync-committee-aggregation-delay", 8*time.Second)
	viper.SetDefault("controller.verify-sync-committee-inclusion", false)
	viper.SetDefault("controller.fast-track.attestations", true)
	viper.SetDefault("controller.fast-track.sync-committees", true)
	viper.SetDefault("controller.fast-track.grace", 500*time.Millisecond)
	viper.SetDefault("blockrelay.timeout", 1*time.Second)
	viper.SetDefault("blockrelay.listen-address", "0.0.0.0:18550")
	viper.SetDefault("blockrelay.fallback-gas-limit", uint64(36000000))
	viper.SetDefault("accountmanager.dirk.timeout", 30*time.Second)
	viper.SetDefault("strategies.beaconblockproposal.best.execution-payload-factor", float64(0.0005))
	viper.SetDefault("beaconblockproposer.builder-boost-factor", 91)
	viper.SetDefault("strategies.builderbid.deadline.deadline", time.Second)
	viper.SetDefault("strategies.builderbid.deadline.bid-gap", 100*time.Millisecond)
	viper.SetDefault("submitter.style", "multinode")
	viper.SetDefault("multiinstance.static-delay.attester-delay", time.Second)
	viper.SetDefault("multiinstance.static-delay.proposer-delay", 2*time.Second)

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
		consensusClient, err = fetchMultiClient(ctx, monitor, "main", viper.GetStringSlice("beacon-node-addresses"))
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
	waitedForGenesis, err := waitForGenesis(ctx, chainTime)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to wait for genesis block")
	}

	altairCapable, bellatrixCapable, err := consensusClientCapabilities(ctx, eth2Client)
	if err != nil {
		return nil, nil, err
	}

	signedBeaconBlockProvider, beaconBlockHeaderProvider, err := startProviderServices(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, err
	}

	schedulerSvc, cacheSvc, signerSvc, accountManager, err := startSharedServices(ctx, eth2Client, majordomo, chainTime, monitor, beaconBlockHeaderProvider, signedBeaconBlockProvider)
	if err != nil {
		return nil, nil, err
	}

	submitter, err := selectSubmitterStrategy(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to select submitter")
	}

	blockRelay, err := startBlockRelay(ctx, majordomo, monitor, eth2Client, schedulerSvc, chainTime, accountManager, signerSvc, cacheSvc)
	if err != nil {
		return nil, nil, err
	}

	beaconBlockProposer, attesterSvc, attestationAggregator, beaconCommitteeSubscriber, err := startSigningServices(ctx,
		majordomo,
		monitor,
		eth2Client,
		chainTime,
		cacheSvc,
		signerSvc,
		blockRelay,
		accountManager,
		submitter,
		signedBeaconBlockProvider,
	)
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

	// We need to submit proposal preparations to all nodes that are acting as beacon block proposers.
	proposalPreparer, err := initProposalPreparer(ctx, monitor, chainTime, bellatrixCapable, accountManager, blockRelay)
	if err != nil {
		return nil, nil, err
	}

	multiInstance, err := startMultiInstance(ctx, monitor, chainTime, eth2Client, beaconBlockHeaderProvider)
	if err != nil {
		return nil, nil, err
	}

	controller, err := initController(ctx,
		monitor,
		chainTime,
		eth2Client,
		schedulerSvc,
		attesterSvc,
		cacheSvc,
		waitedForGenesis,
		accountManager,
		beaconBlockProposer,
		signedBeaconBlockProvider,
		proposalPreparer,
		attestationAggregator,
		beaconCommitteeSubscriber,
		syncCommitteeMessenger,
		syncCommitteeAggregator,
		syncCommitteeSubscriber,
		beaconBlockHeaderProvider,
		multiInstance,
	)
	if err != nil {
		return nil, nil, err
	}

	return chainTime, controller, nil
}

func initController(ctx context.Context,
	monitor metrics.Service,
	chainTime chaintime.Service,
	eth2Client eth2client.Service,
	schedulerSvc scheduler.Service,
	attesterSvc attester.Service,
	cacheSvc cache.Service,
	waitedForGenesis bool,
	accountManager accountmanager.Service,
	beaconBlockProposer beaconblockproposer.Service,
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
	proposalPreparer proposalpreparer.Service,
	attestationAggregator attestationaggregator.Service,
	beaconCommitteeSubscriber beaconcommitteesubscriber.Service,
	syncCommitteeMessenger synccommitteemessenger.Service,
	syncCommitteeAggregator synccommitteeaggregator.Service,
	syncCommitteeSubscriber synccommitteesubscriber.Service,
	beaconBlockHeaderProvider eth2client.BeaconBlockHeadersProvider,
	multiInstance multiinstance.Service,
) (
	*standardcontroller.Service,
	error,
) {
	// The events provider for the controller should only use beacon nodes that are used for attestation data.
	eventsConsensusClient, err := fetchMultiClient(ctx, monitor, "events", util.BeaconNodeAddressesForAttesting())
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch multiclient for controller")
	}

	log.Trace().Msg("Starting controller")
	controller, err := standardcontroller.New(ctx,
		standardcontroller.WithLogLevel(util.LogLevel("controller")),
		standardcontroller.WithMonitor(monitor),
		standardcontroller.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardcontroller.WithChainTimeService(chainTime),
		standardcontroller.WithWaitedForGenesis(waitedForGenesis),
		standardcontroller.WithProposerDutiesProvider(eth2Client.(eth2client.ProposerDutiesProvider)),
		standardcontroller.WithAttesterDutiesProvider(eth2Client.(eth2client.AttesterDutiesProvider)),
		standardcontroller.WithSyncCommitteeDutiesProvider(eth2Client.(eth2client.SyncCommitteeDutiesProvider)),
		standardcontroller.WithEventsProvider(eventsConsensusClient.(eth2client.EventsProvider)),
		standardcontroller.WithScheduler(schedulerSvc),
		standardcontroller.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardcontroller.WithAttester(attesterSvc),
		standardcontroller.WithSyncCommitteeMessenger(syncCommitteeMessenger),
		standardcontroller.WithSyncCommitteeAggregator(syncCommitteeAggregator),
		standardcontroller.WithBeaconBlockProposer(beaconBlockProposer),
		standardcontroller.WithBeaconBlockHeadersProvider(beaconBlockHeaderProvider),
		standardcontroller.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
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
		standardcontroller.WithVerifySyncCommitteeInclusion(viper.GetBool("controller.verify-sync-committee-inclusion")),
		standardcontroller.WithFastTrackAttestations(viper.GetBool("controller.fast-track.attestations")),
		standardcontroller.WithFastTrackSyncCommittees(viper.GetBool("controller.fast-track.sync-committees")),
		standardcontroller.WithFastTrackGrace(viper.GetDuration("controller.fast-track.grace")),
		standardcontroller.WithMultiInstance(multiInstance),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to start controller service")
	}
	return controller, nil
}

func initProposalPreparer(ctx context.Context, monitor metrics.Service, chainTime chaintime.Service, bellatrixCapable bool, accountManager accountmanager.Service, blockRelay blockrelay.Service) (proposalpreparer.Service, error) {
	// We need to submit proposal preparations to all nodes that are acting as beacon block proposers.
	nodeAddresses := util.BeaconNodeAddressesForProposing()
	proposalPreparationsSubmitters := make([]eth2client.ProposalPreparationsSubmitter, 0, len(nodeAddresses))
	for _, address := range nodeAddresses {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for proposal preparation submitter", address))
		}
		proposalPreparationsSubmitters = append(proposalPreparationsSubmitters, client.(eth2client.ProposalPreparationsSubmitter))
	}

	if bellatrixCapable {
		log.Trace().Msg("Starting proposals preparer")
		proposalPreparer, err := standardproposalpreparer.New(ctx,
			standardproposalpreparer.WithLogLevel(util.LogLevel("proposalspreparor")),
			standardproposalpreparer.WithMonitor(monitor),
			standardproposalpreparer.WithChainTimeService(chainTime),
			standardproposalpreparer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
			standardproposalpreparer.WithProposalPreparationsSubmitters(proposalPreparationsSubmitters),
			standardproposalpreparer.WithExecutionConfigProvider(blockRelay.(blockrelay.ExecutionConfigProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start proposal preparer service")
		}
		return proposalPreparer, nil
	}
	var proposalPreparer proposalpreparer.Service
	return proposalPreparer, nil
}

func waitForGenesis(ctx context.Context, chainTime chaintime.Service) (bool, error) {
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
			return false, errors.New("signal received")
		case <-ctx.Done():
			switch ctx.Err() {
			case context.DeadlineExceeded:
				log.Info().Msg("Genesis time")
			case context.Canceled:
				return false, errors.New("context cancelled")
			}
		}
	}
	return waitedForGenesis, nil
}

func startProviderServices(ctx context.Context, monitor metrics.Service, eth2Client eth2client.Service) (eth2client.SignedBeaconBlockProvider, eth2client.BeaconBlockHeadersProvider, error) {
	// The signed beacon block provider from the configured strategy to define how we get signed beacon blocks.
	signedBeaconBlockProvider, err := selectSignedBeaconBlockProvider(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to fetch signed beacon block provider for controller")
	}

	// The block header provider from the configured strategy to define how we get block headers.
	beaconBlockHeaderProvider, err := selectBeaconHeaderProvider(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to fetch beacon block header provider for controller")
	}
	return signedBeaconBlockProvider, beaconBlockHeaderProvider, nil
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
	beaconBlockHeaderProvider eth2client.BeaconBlockHeadersProvider,
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
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
	cacheSvc, err := startCache(ctx, monitor, chainTime, scheduler, eth2Client, beaconBlockHeaderProvider, signedBeaconBlockProvider)
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
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
) (
	graffitiprovider.Service,
	eth2client.ProposalProvider,
	eth2client.AttestationDataProvider,
	eth2client.AggregateAttestationProvider,
	error,
) {
	log.Trace().Msg("Starting graffiti provider")
	graffitiProvider, err := startGraffitiProvider(ctx, majordomo)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start graffiti provider")
	}

	log.Trace().Msg("Selecting beacon block proposal provider")
	beaconBlockProposalProvider, err := selectProposalProvider(ctx, monitor, eth2Client, chainTime, cache, signedBeaconBlockProvider)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to select beacon block proposal provider")
	}

	log.Trace().Msg("Selecting attestation data provider")
	attestationDataProvider, err := selectAttestationDataProvider(ctx, monitor, eth2Client, chainTime, cache)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to select attestation data provider")
	}

	log.Trace().Msg("Selecting aggregate attestation provider")
	aggregateAttestationProvider, err := selectAggregateAttestationProvider(ctx, monitor, eth2Client)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to select aggregate attestation provider")
	}

	return graffitiProvider, beaconBlockProposalProvider, attestationDataProvider, aggregateAttestationProvider, nil
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
		standardsynccommitteesubscriber.WithMonitor(monitor),
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
		standardsynccommitteeaggregator.WithMonitor(monitor),
		standardsynccommitteeaggregator.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardsynccommitteeaggregator.WithBeaconBlockRootProvider(beaconBlockRootProvider),
		standardsynccommitteeaggregator.WithContributionAndProofSigner(signerSvc.(signer.ContributionAndProofSigner)),
		standardsynccommitteeaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardsynccommitteeaggregator.WithSyncCommitteeContributionProvider(syncCommitteeContributionProvider),
		standardsynccommitteeaggregator.WithSyncCommitteeContributionsSubmitter(submitterStrategy.(submitter.SyncCommitteeContributionsSubmitter)),
		standardsynccommitteeaggregator.WithChainTime(chainTime),
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to start sync committee aggregator service")
	}

	log.Trace().Msg("Starting sync committee messenger")
	syncCommitteeMessenger, err := standardsynccommitteemessenger.New(ctx,
		standardsynccommitteemessenger.WithLogLevel(util.LogLevel("synccommitteemessenger")),
		standardsynccommitteemessenger.WithProcessConcurrency(viper.GetInt64("process-concurrency")),
		standardsynccommitteemessenger.WithMonitor(monitor),
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
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
) (
	beaconblockproposer.Service,
	attester.Service,
	attestationaggregator.Service,
	beaconcommitteesubscriber.Service,
	error,
) {
	graffitiProvider, proposalProvider, attestationDataProvider, aggregateAttestationProvider, err := startProviders(ctx,
		majordomo,
		monitor,
		eth2Client,
		chainTime,
		cacheSvc,
		signedBeaconBlockProvider,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	beaconBlockProposer, err := standardbeaconblockproposer.New(ctx,
		standardbeaconblockproposer.WithLogLevel(util.LogLevel("beaconblockproposer")),
		standardbeaconblockproposer.WithChainTime(chainTime),
		standardbeaconblockproposer.WithProposalDataProvider(proposalProvider),
		standardbeaconblockproposer.WithBlockAuctioneer(blockRelay.(blockauctioneer.BlockAuctioneer)),
		standardbeaconblockproposer.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardbeaconblockproposer.WithExecutionChainHeadProvider(cacheSvc.(cache.ExecutionChainHeadProvider)),
		standardbeaconblockproposer.WithGraffitiProvider(graffitiProvider),
		standardbeaconblockproposer.WithMonitor(monitor),
		standardbeaconblockproposer.WithProposalSubmitter(submitterStrategy.(submitter.ProposalSubmitter)),
		standardbeaconblockproposer.WithRANDAORevealSigner(signerSvc.(signer.RANDAORevealSigner)),
		standardbeaconblockproposer.WithBeaconBlockSigner(signerSvc.(signer.BeaconBlockSigner)),
		standardbeaconblockproposer.WithBlobSidecarSigner(signerSvc.(signer.BlobSidecarSigner)),
		standardbeaconblockproposer.WithUnblindFromAllRelays(viper.GetBool("beaconblockproposer.unblind-from-all-relays")),
		standardbeaconblockproposer.WithBuilderBoostFactor(viper.GetUint64("beaconblockproposer.builder-boost-factor")),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start beacon block proposer service")
	}

	log.Trace().Msg("Starting attester")
	attester, err := standardattester.New(ctx,
		standardattester.WithLogLevel(util.LogLevel("attester")),
		standardattester.WithProcessConcurrency(util.ProcessConcurrency("attester")),
		standardattester.WithGrace(viper.GetDuration("attester.grace")),
		standardattester.WithChainTime(chainTime),
		standardattester.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardattester.WithAttestationDataProvider(attestationDataProvider),
		standardattester.WithAttestationsSubmitter(submitterStrategy.(submitter.AttestationsSubmitter)),
		standardattester.WithMonitor(monitor),
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
		standardattestationaggregator.WithMonitor(monitor),
		standardattestationaggregator.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardattestationaggregator.WithSlotSelectionSigner(signerSvc.(signer.SlotSelectionSigner)),
		standardattestationaggregator.WithAggregateAndProofSigner(signerSvc.(signer.AggregateAndProofSigner)),
		standardattestationaggregator.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
		standardattestationaggregator.WithChainTime(chainTime),
	)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to start beacon attestation aggregator service")
	}

	log.Trace().Msg("Starting beacon committee subscriber service")
	beaconCommitteeSubscriber, err := standardbeaconcommitteesubscriber.New(ctx,
		standardbeaconcommitteesubscriber.WithLogLevel(util.LogLevel("beaconcommiteesubscriber")),
		standardbeaconcommitteesubscriber.WithProcessConcurrency(util.ProcessConcurrency("beaconcommitteesubscriber")),
		standardbeaconcommitteesubscriber.WithMonitor(monitor),
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
	if viper.GetString("metrics.prometheus.listen-address") != "" {
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
		monitor = nullmetrics.New()
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
			advancedscheduler.WithMonitor(monitor),
		)
	default:
		log.Info().Msg("Starting advanced scheduler")
		scheduler, err = advancedscheduler.New(ctx,
			advancedscheduler.WithLogLevel(util.LogLevel("scheduler.advanced")),
			advancedscheduler.WithMonitor(monitor),
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
	beaconBlockHeaderProvider eth2client.BeaconBlockHeadersProvider,
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
) (cache.Service, error) {
	log.Trace().Msg("Starting cache")
	cache, err := standardcache.New(ctx,
		standardcache.WithLogLevel(util.LogLevel("cache.standard")),
		standardcache.WithMonitor(monitor),
		standardcache.WithScheduler(scheduler),
		standardcache.WithChainTime(chainTime),
		standardcache.WithEventsProvider(consensusClient.(eth2client.EventsProvider)),
		standardcache.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
		standardcache.WithBeaconBlockHeadersProvider(beaconBlockHeaderProvider),
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
			dynamicgraffitiprovider.WithFallbackLocation(viper.GetString("graffiti.dynamic.fallback-location")),
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
			dirkaccountmanager.WithMonitor(monitor),
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
			walletaccountmanager.WithMonitor(monitor),
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
	case "majority":
		log.Info().Msg("Starting majority attestation data strategy")
		attestationDataProviders := make(map[string]eth2client.AttestationDataProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.attestationdata.majority") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for attestation data strategy", address))
			}
			attestationDataProviders[address] = client.(eth2client.AttestationDataProvider)
		}
		attestationDataProvider, err = majorityattestationdatastrategy.New(ctx,
			majorityattestationdatastrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			majorityattestationdatastrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.attestationdata.majority")),
			majorityattestationdatastrategy.WithLogLevel(util.LogLevel("strategies.attestationdata.majority")),
			majorityattestationdatastrategy.WithAttestationDataProviders(attestationDataProviders),
			majorityattestationdatastrategy.WithTimeout(util.Timeout("strategies.attestationdata.majority")),
			majorityattestationdatastrategy.WithChainTime(chainTime),
			majorityattestationdatastrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			majorityattestationdatastrategy.WithThreshold(viper.GetInt("strategies.attestationdata.majority.threshold")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start majority attestation data strategy")
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
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider,
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
			bestbeaconblockproposalstrategy.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
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
			majoritybeaconblockrootstrategy.WithProcessConcurrency(util.ProcessConcurrency("strategies.beaconblockroot.majority")),
			majoritybeaconblockrootstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockroot.majority")),
			majoritybeaconblockrootstrategy.WithBeaconBlockRootProviders(beaconBlockRootProviders),
			majoritybeaconblockrootstrategy.WithTimeout(util.Timeout("strategies.beaconblockroot.majority")),
			majoritybeaconblockrootstrategy.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start majority sync committee contribution strategy")
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
	case "latest":
		log.Info().Msg("Starting latest beacon block root strategy")
		beaconBlockRootProviders := make(map[string]eth2client.BeaconBlockRootProvider)
		for _, address := range util.BeaconNodeAddresses("strategies.beaconblockroot.latest") {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block root strategy", address))
			}
			beaconBlockRootProviders[address] = client.(eth2client.BeaconBlockRootProvider)
		}
		beaconBlockRootProvider, err = latestbeaconblockrootstrategy.New(ctx,
			latestbeaconblockrootstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			latestbeaconblockrootstrategy.WithLogLevel(util.LogLevel("strategies.beaconblockroot.latest")),
			latestbeaconblockrootstrategy.WithBeaconBlockRootProviders(beaconBlockRootProviders),
			latestbeaconblockrootstrategy.WithTimeout(util.Timeout("strategies.beaconblockroot.latest")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start latest beacon block root strategy")
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

func genericAddressToClientMapper[T any](ctx context.Context, monitor metrics.Service, path, description string) (map[string]T, error) {
	addressToClientMap := make(map[string]T)
	for _, address := range util.BeaconNodeAddresses(path) {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for %s", address, description))
		}
		clientCast, ok := client.(T)
		if !ok {
			return nil, fmt.Errorf("failed to cast client %s for %s", address, description)
		}
		addressToClientMap[address] = clientCast
	}
	return addressToClientMap, nil
}

func startMultinodeSubmitter(ctx context.Context,
	monitor metrics.Service,
) (
	submitter.Service,
	error,
) {
	aggregateAttestationSubmitters, err := genericAddressToClientMapper[eth2client.AggregateAttestationsSubmitter](ctx, monitor,
		"submitter.aggregateattestation.multinode",
		"aggregate attestation submitter strategy")
	if err != nil {
		return nil, err
	}

	attestationsSubmitters, err := genericAddressToClientMapper[eth2client.AttestationsSubmitter](ctx, monitor,
		"submitter.attestation.multinode",
		"attestation submitter strategy")
	if err != nil {
		return nil, err
	}

	proposalSubmitters, err := genericAddressToClientMapper[eth2client.ProposalSubmitter](ctx, monitor,
		"submitter.proposal.multinode",
		"proposal submitter strategy")
	if err != nil {
		return nil, err
	}

	beaconCommitteeSubscriptionsSubmitters, err := genericAddressToClientMapper[eth2client.BeaconCommitteeSubscriptionsSubmitter](ctx, monitor,
		"submitter.beaconcommitteesubscription.multinode",
		"beacon committee subscription submitter strategy")
	if err != nil {
		return nil, err
	}

	proposalPreparationSubmitters, err := genericAddressToClientMapper[eth2client.ProposalPreparationsSubmitter](ctx, monitor,
		"submitter.proposalpreparation.multinode",
		"proposal preparation submitter strategy")
	if err != nil {
		return nil, err
	}

	syncCommitteeContributionsSubmitters, err := genericAddressToClientMapper[eth2client.SyncCommitteeContributionsSubmitter](ctx, monitor,
		"submitter.synccommitteecontribution.multinode",
		"sync committee contribution submitter strategy")
	if err != nil {
		return nil, err
	}

	syncCommitteeMessagesSubmitters, err := genericAddressToClientMapper[eth2client.SyncCommitteeMessagesSubmitter](ctx, monitor,
		"submitter.synccommitteemessage.multinode",
		"sync committee message submitter strategy")
	if err != nil {
		return nil, err
	}

	syncCommitteeSubscriptionsSubmitters, err := genericAddressToClientMapper[eth2client.SyncCommitteeSubscriptionsSubmitter](ctx, monitor,
		"submitter.synccommitteesubscription.multinode",
		"sync committee subscription submitter strategy")
	if err != nil {
		return nil, err
	}

	submitterService, err := multinodesubmitter.New(ctx,
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

	return submitterService, nil
}

// runCommands potentially runs commands.
// Returns true if Vouch should exit.
func runCommands(ctx context.Context,
	majordomo majordomo.Service,
) bool {
	if viper.GetBool("version") {
		fmt.Fprintf(os.Stdout, "%s\n", ReleaseVersion)
		return true
	}

	if viper.GetString("proposer-config-check") != "" {
		return proposerConfigCheck(ctx, majordomo)
	}

	return false
}

func consensusClientCapabilities(ctx context.Context, consensusClient eth2client.Service) (bool, bool, error) {
	// Decide if the ETH2 client is capable of Altair.
	altairCapable := false
	specResponse, err := consensusClient.(eth2client.SpecProvider).Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return false, false, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data
	if _, exists := spec["ALTAIR_FORK_EPOCH"]; exists {
		altairCapable = true
	} else {
		log.Warn().Msg("Client is not Altair-capable")
	}

	// Decide if the ETH2 client is capable of Bellatrix.
	bellatrixCapable := false
	if _, exists := spec["BELLATRIX_FORK_EPOCH"]; exists {
		bellatrixCapable = true
	} else {
		log.Warn().Msg("Client is not Bellatrix-capable")
	}

	// Check if the ETH2 client is capable of Fulu.
	if _, exists := spec["FULU_FORK_EPOCH"]; exists {
		log.Info().Msg("Client is Fulu-capable")
	} else {
		log.Warn().Msg("Client is not Fulu-capable")
	}

	return altairCapable, bellatrixCapable, nil
}

func startBlockRelay(ctx context.Context,
	majordomo majordomo.Service,
	monitor metrics.Service,
	eth2Client eth2client.Service,
	scheduler scheduler.Service,
	chainTime chaintime.Service,
	accountManager accountmanager.Service,
	signerSvc signer.Service,
	cacheSvc cache.Service,
) (
	blockrelay.Service,
	error,
) {
	builderBidProvider, err := selectBuilderBidProvider(ctx, monitor, eth2Client, chainTime, cacheSvc)
	if err != nil {
		return nil, err
	}

	// We also need to submit validator registrations to all nodes that are acting as blinded beacon block proposers, as
	// some of them use the registration as part of the condition to decide if the blinded block should be called or not.
	nodeAddresses := util.BeaconNodeAddressesForProposing()
	secondaryValidatorRegistrationsSubmitters := make([]eth2client.ValidatorRegistrationsSubmitter, 0, len(nodeAddresses))
	for _, address := range nodeAddresses {
		client, err := fetchClient(ctx, monitor, address)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for secondary validator registration", address))
		}
		secondaryValidatorRegistrationsSubmitters = append(secondaryValidatorRegistrationsSubmitters, client.(eth2client.ValidatorRegistrationsSubmitter))
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
	if fallbackFeeRecipient.IsZero() {
		return nil, errors.New("blockrelay: fee recipient supplied is zero")
	}

	builderConfigs, err := obtainBuilderConfigs(ctx)
	if err != nil {
		return nil, err
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
		standardblockrelay.WithValidatorsProvider(eth2Client.(eth2client.ValidatorsProvider)),
		standardblockrelay.WithValidatingAccountsProvider(accountManager.(accountmanager.ValidatingAccountsProvider)),
		standardblockrelay.WithListenAddress(viper.GetString("blockrelay.listen-address")),
		standardblockrelay.WithValidatorRegistrationSigner(signerSvc.(signer.ValidatorRegistrationSigner)),
		standardblockrelay.WithSecondaryValidatorRegistrationsSubmitters(secondaryValidatorRegistrationsSubmitters),
		standardblockrelay.WithLogResults(viper.GetBool("blockrelay.log-results")),
		standardblockrelay.WithReleaseVersion(ReleaseVersion),
		standardblockrelay.WithBuilderBidProvider(builderBidProvider),
		standardblockrelay.WithBuilderConfigs(builderConfigs),
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
	cacheSvc cache.Service,
) (
	builderbid.Provider,
	error,
) {
	log.Trace().Msg("Selecting builder bid strategy")

	var provider builderbid.Provider
	var err error

	switch viper.GetString("strategies.builderbid.style") {
	case "deadline":
		log.Info().Msg("Starting deadline builder bid strategy")
		provider, err = deadlinebuilderbidstrategy.New(ctx,
			deadlinebuilderbidstrategy.WithLogLevel(util.LogLevel("strategies.builderbid.deadline")),
			deadlinebuilderbidstrategy.WithMonitor(monitor),
			deadlinebuilderbidstrategy.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			deadlinebuilderbidstrategy.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
			deadlinebuilderbidstrategy.WithBlockGasLimitProvider(cacheSvc.(cache.BlockGasLimitProvider)),
			deadlinebuilderbidstrategy.WithChainTime(chainTime),
			deadlinebuilderbidstrategy.WithDeadline(viper.GetDuration("strategies.builderbid.deadline.deadline")),
			deadlinebuilderbidstrategy.WithBidGap(viper.GetDuration("strategies.builderbid.deadline.bid-gap")),
			deadlinebuilderbidstrategy.WithReleaseVersion(ReleaseVersion),
		)
	case "best", "":
		log.Info().Msg("Starting best builder bid strategy")
		provider, err = bestbuilderbidstrategy.New(ctx,
			bestbuilderbidstrategy.WithLogLevel(util.LogLevel("strategies.builderbid.best")),
			bestbuilderbidstrategy.WithMonitor(monitor),
			bestbuilderbidstrategy.WithSpecProvider(eth2Client.(eth2client.SpecProvider)),
			bestbuilderbidstrategy.WithDomainProvider(eth2Client.(eth2client.DomainProvider)),
			bestbuilderbidstrategy.WithBlockGasLimitProvider(cacheSvc.(cache.BlockGasLimitProvider)),
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

func obtainBuilderConfigs(ctx context.Context) (map[phase0.BLSPubKey]*blockrelay.BuilderConfig, error) {
	res := make(map[phase0.BLSPubKey]*blockrelay.BuilderConfig)

	if err := obtainBuilderConfigsForExcludedBuilders(ctx, res); err != nil {
		return nil, err
	}
	if err := obtainBuilderConfigsForPrivilegedBuilders(ctx, res); err != nil {
		return nil, err
	}

	for addr := range viper.GetStringMap("blockrelay.builder-configs") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode builder public key %s", addr)
		}
		if len(tmp) != phase0.PublicKeyLength {
			return nil, fmt.Errorf("incorrect length for builder public key %s", addr)
		}
		var publicKey phase0.BLSPubKey
		copy(publicKey[:], tmp)

		category := blockrelay.StandardBuilderCategory
		var factor *big.Int
		var offset *big.Int

		var success bool
		for k, v := range viper.GetStringMapString(fmt.Sprintf("blockrelay.builder-configs.%s", addr)) {
			switch {
			case strings.EqualFold(k, "category"):
				category = v
			case strings.EqualFold(k, "factor"):
				factor, success = new(big.Int).SetString(v, 10)
				if !success {
					return nil, fmt.Errorf("failed to decode factor %s for builder %s", v, addr)
				}
				if factor.Sign() == -1 {
					return nil, fmt.Errorf("factor %s cannot be negative for builder %s", v, addr)
				}
			case strings.EqualFold(k, "offset"):
				offset, success = new(big.Int).SetString(v, 10)
				if !success {
					return nil, fmt.Errorf("failed to decode offset %s for builder %s", v, addr)
				}
			}
		}

		res[publicKey] = &blockrelay.BuilderConfig{
			Category: category,
			Factor:   factor,
			Offset:   offset,
		}
	}

	return res, nil
}

func obtainBuilderConfigsForExcludedBuilders(_ context.Context,
	res map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) error {
	if viper.Get("blockrelay.excluded-builders") != nil {
		log.Warn().Msg("blockrelay.excluded-builders is deprecated; please use blockrelay.builder-configs")
	}
	for _, addr := range viper.GetStringSlice("blockrelay.excluded-builders") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
		if err != nil {
			return errors.Wrapf(err, "failed to decode builder public key %s", addr)
		}
		if len(tmp) != phase0.PublicKeyLength {
			return fmt.Errorf("incorrect length for builder public key %s", addr)
		}
		var publicKey phase0.BLSPubKey
		copy(publicKey[:], tmp)

		res[publicKey] = &blockrelay.BuilderConfig{
			Category: "excluded",
			Factor:   big.NewInt(0),
		}
	}

	return nil
}

func obtainBuilderConfigsForPrivilegedBuilders(_ context.Context,
	res map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) error {
	if viper.Get("blockrelay.privileged-builders") != nil {
		log.Warn().Msg("blockrelay.privileged-builders is deprecated; please use blockrelay.builder-configs")
	}
	for _, addr := range viper.GetStringSlice("blockrelay.privileged-builders") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
		if err != nil {
			return errors.Wrapf(err, "failed to decode builder public key %s", addr)
		}
		if len(tmp) != phase0.PublicKeyLength {
			return fmt.Errorf("incorrect length for builder public key %s", addr)
		}
		var publicKey phase0.BLSPubKey
		copy(publicKey[:], tmp)

		res[publicKey] = &blockrelay.BuilderConfig{
			Category: "privileged",
			Factor:   big.NewInt(1000000000000000000),
		}
	}

	return nil
}

// select the signed beacon block provider based on user input.
func selectSignedBeaconBlockProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (
	eth2client.SignedBeaconBlockProvider,
	error,
) {
	log.Trace().Msg("Selecting signed beacon block strategy")

	var provider eth2client.SignedBeaconBlockProvider
	var err error

	style := "strategies.signedbeaconblock.style"
	switch viper.GetString(style) {
	case "first", "":
		log.Info().Msg("Starting first signed beacon block strategy")
		signedBeaconBlockProviders := make(map[string]eth2client.SignedBeaconBlockProvider)
		path := "strategies.signedbeaconblock.first"
		for _, address := range util.BeaconNodeAddresses(path) {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for signed beacon block strategy", address))
			}
			signedBeaconBlockProviders[address] = client.(eth2client.SignedBeaconBlockProvider)
		}

		provider, err = firstsignedbeaconblockstrategy.New(ctx,
			firstsignedbeaconblockstrategy.WithTimeout(util.Timeout(path)),
			firstsignedbeaconblockstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstsignedbeaconblockstrategy.WithLogLevel(util.LogLevel(path)),
			firstsignedbeaconblockstrategy.WithSignedBeaconBlockProviders(signedBeaconBlockProviders),
		)
	default:
		log.Info().Msg("Starting simple signed block strategy")
		provider = eth2Client.(eth2client.SignedBeaconBlockProvider)
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate signed beacon block strategy")
	}

	return provider, nil
}

// select the beacon header provider based on user input.
func selectBeaconHeaderProvider(ctx context.Context,
	monitor metrics.Service,
	eth2Client eth2client.Service,
) (
	eth2client.BeaconBlockHeadersProvider,
	error,
) {
	log.Trace().Msg("Selecting beacon header strategy")

	var provider eth2client.BeaconBlockHeadersProvider
	var err error

	style := "strategies.beaconblockheader.style"
	switch viper.GetString(style) {
	case "first", "":
		log.Info().Msg("Starting first beacon block header strategy")
		beaconBlockHeaderProviders := make(map[string]eth2client.BeaconBlockHeadersProvider)
		path := "strategies.beaconblockheader.first"
		for _, address := range util.BeaconNodeAddresses(path) {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for beacon block header strategy", address))
			}
			beaconBlockHeaderProviders[address] = client.(eth2client.BeaconBlockHeadersProvider)
		}

		provider, err = firstbeaconblockheaderstrategy.New(ctx,
			firstbeaconblockheaderstrategy.WithTimeout(util.Timeout(path)),
			firstbeaconblockheaderstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			firstbeaconblockheaderstrategy.WithLogLevel(util.LogLevel(path)),
			firstbeaconblockheaderstrategy.WithBeaconBlockHeadersProviders(beaconBlockHeaderProviders),
		)
	default:
		log.Info().Msg("Starting simple beacon block header strategy")
		provider = eth2Client.(eth2client.BeaconBlockHeadersProvider)
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate beacon header strategy")
	}

	return provider, nil
}

func startMultiInstance(ctx context.Context,
	monitor metrics.Service,
	chainTime chaintime.Service,
	consensusClient eth2client.Service,
	beaconBlockHeadersProvider eth2client.BeaconBlockHeadersProvider,
) (multiinstance.Service, error) {
	var service multiinstance.Service
	var err error

	switch viper.GetString("multiinstance.style") {
	case "static-delay":
		log.Info().Msg("Starting static delay multi instance system")

		attestationPoolProviders := make(map[string]eth2client.AttestationPoolProvider)
		path := "strategies.attestationpool.combined"
		for _, address := range util.BeaconNodeAddresses(path) {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to fetch client %s for attestation pool strategy", address))
			}
			attestationPoolProviders[address] = client.(eth2client.AttestationPoolProvider)
		}
		var attestationPoolProvider eth2client.AttestationPoolProvider
		attestationPoolProvider, err = combinedattestationpoolstrategy.New(ctx,
			combinedattestationpoolstrategy.WithLogLevel(util.LogLevel("strategies.attestationpool.combined")),
			combinedattestationpoolstrategy.WithClientMonitor(monitor.(metrics.ClientMonitor)),
			combinedattestationpoolstrategy.WithTimeout(util.Timeout("strategies.attestationpool")),
			combinedattestationpoolstrategy.WithAttestationPoolProviders(attestationPoolProviders),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to instantiate attestation pool strategy")
		}

		service, err = staticdelaymultiinstance.New(ctx,
			staticdelaymultiinstance.WithLogLevel(util.LogLevel("multiinstance.static-delay")),
			staticdelaymultiinstance.WithMonitor(monitor),
			staticdelaymultiinstance.WithAttestationPoolProvider(attestationPoolProvider),
			staticdelaymultiinstance.WithSpecProvider(consensusClient.(eth2client.SpecProvider)),
			staticdelaymultiinstance.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
			staticdelaymultiinstance.WithChainTime(chainTime),
			staticdelaymultiinstance.WithAttesterDelay(viper.GetDuration("multiinstance.static-delay.attester-delay")),
			staticdelaymultiinstance.WithProposerDelay(viper.GetDuration("multiinstance.static-delay.proposer-delay")),
		)
	default:
		service, err = alwaysmultiinstance.New(ctx,
			alwaysmultiinstance.WithLogLevel(util.LogLevel("multiinstance.always")),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to start multi instance service")
	}

	return service, nil
}
