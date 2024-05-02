dev:
  - update internal active validators count when Dirk not available at start

1.9.0-alpha.3
  - add proposal value and blinded status to trace
  - add beaconblockproposer.builder-boost-factor
  - add reduced memory mode for memory-constrained systems
  - reduce memory usage when obtaining Dirk accounts
  - reduce memory usage when generating beacon committee subscriptions
  - add "controller.fast-track" flag

1.9.0-alpha.2:
  - allow Vouch to act as an MEV-boost client for non-Vouch validators
  - increase proposal performance with new validator REST APIs

1.9.0-alpha.1:
  - reduce time spent verifying account names
  - ensure that attestations complete on Vouch's first ever epoch
  - allow Vouch to start with some consensus nodes unavailable

1.8.0:
  - support Deneb
  - reject block proposals with 0 fee recipient
  - ensure all relevant beacon nodes receive proposal preparations
  - ensure relay configuration inherits all configuration values as expected
  - create strategies for builder bid
  - fetch blinded and unblinded proposals in parallel to speed up block production
  - compose multiclients from clients, reducing connections to beacon nodes
  - start validator registrations randomly in middle 80% of each epoch, to avoid overloading relays
  - reduce CPU and memory requirements for refreshing validator information
  - implement exclusion list for builders
  - add option to attempt unblinding of payloads from all contacted relays
  - add "majority" attestation data strategy
  - allow MEV relay re-registration of previously registered data

1.7.6:
  - add User-Agent header to HTTP requests
  - controller only uses beacon nodes that are used for attestation data
  - fix crash if beacon node returns nil block during cache update
  - add score to blinded block proposal trace
  - increase speed of validator registration generation, reduce memory usage
  - add strategies to obtain the beacon block root
  - add bid selection trace attributes to AuctionBlock

1.7.5:
  - add score of block proposals to tracing
  - remove unnecessary trace item when attesting
  - add execution payload metric to beacon block score

1.7.3:
  - do not start account managers unnecessarily
  - fail if multiple account managers are defined

1.7.2:
  - update dependencies
  - provide more detail in logs on block proposal mismatches
  - avoid potential failure when proposing local blocks

1.7.1:
  - provide full information for beacon committee subscriptions
  - verify bid signatures from relays if public key available
  - make execution configuration values hierarchical
  - mark nil responses from beacon nodes as errors rather than dropping silently
  - update tracing implementation to use opentelemetry
  - support version 2 of execution configuration; see docs/execlayer.md for details
  - support Capella
  - update dirk module to reduce number of concurrent connections
  - provide timeout option for remote dirk interactions
  - unblind blocks from all relays that hold the desired payload
  - provide more error information when beacon nodes fail to return expected information
  - reject blinded blocks with incorrect data before scoring
  - update internal cache with events as they arrive for faster block proposal

1.6.3:
  - fix crash attempting to store metrics when prometheus not enabled

1.6.2:
  - fix crash on failure to propose a block
  - log auction results with the `blockrelay.log-results` flag

1.6.1:
  - fix bug where soft timeout message could repeat rapidly
  - clean up control flow and logging for relay situations such as not returning any bid

1.6.0:
  - add block relay module, to handle interactions with MEV relays

1.5.0:
  - add soft timeout to "best" strategies: return half way through the timeout if results have been obtained
  - wait until any attestations for the current slot have completed before shutting down
  - send errors to stderr before logging is ready
  - support Bellatrix
  - add 'fee recipient' service to obtain fee recipients from local or remote source
  - ensure that attestations are created for slot 0
  - poll more frequently for accounts if current set is empty
  - introduce a block root to slot cache to speed up scoring attestations and block proposals
  - provide more useful error messages if Vouch's configuration is unavailable or corrupt
  - add standard CA certificates to docker image
  - add hierarchical configuration of beacon node addresses and other elements; see docs/configuration.md for details

1.4.0:
  - increase accuracy of beacon block proposal scorer by incorporating attestation history
  - multinode submitter returns after first successful submission rather than waiting for all to complete
  - do not send beacon committee subscriptions for current or previous slots on startup

1.3.2:
  - fix crash if beacon block root is returned as nil
  - separate multiclient cache from individual client cache

1.3.1:
  - prepare sync committee duties a few epochs before change of period
  - add `controller.max-proposal-delay` option
  - integrate multi-client consensus client connections.  See configuration documentation for details.

1.3.0:
  - make scheduler channels asynchronous, to avoid potential deadlock
  - add metrics for sync committee operations
  - add `controller.max-attestation-aggregation-delay` option
  - add `controller.sync-committee-message-delay` option
  - add `controller.sync-committee-aggregation-delay` option
  - submit attestations in batches, to speed up initial broadcast
  - add mark metrics, to provide timeliness information for validator operations
  - break down scheduler job start metrics by class
  - add last slot metrics, to track the last slot handled for validator operations
  - remove basic scheduler; advanced scheduler is currently the only supported option

1.2.2:
  - fix crash when no metrics configuration is supplied

1.2.1:
  - make advanced scheduler the default
  - do not process empty sync committee messages
  - avoid deadlock in advanced scheduler

1.2.0:
  - fetch attestation duties for next epoch approximately half way through current epoch
  - remove spurious warning for duplicate submission of sync committee messages
  - decrypt local accounts in parallel to reduce startup time
  - add individual strategy timeouts for finer control of strategies
  - add 'advanced' scheduler, designed to be more robust with higher parallel job load
  - fetch wallet accounts from Dirk in parallel
  - fetch process-concurrency configuration value from most specific point in hierarchy
  - add metrics to track strategy operation results
  - support Altair:
    - support updated `go-eth2-client` for versioned data
    - manage sync committee operations:
      - generate sync committee messages
      - act as sync committee aggregator as required
  - added metrics to track strategy operation results
  - provide release metric in `vouch_release`
  - provide ready metric in `vouch_ready`
  - handle chain reorganisations, updating duties as appropriate
  - add `controller.max_attestation_delay` option
  - introduce aggregate attestation strategy, allowing selection of best or first aggregate attestation from a set
  - add 'epoch_slot' label to 'vouch_block_receipt_delay_seconds' metric

1.0.4:
  - retain existing validator list if an attempted refresh returns no results
  - avoid crash when a Vouch cannot obtain the RANDAO reveal for a block proposal

1.0.3:
  - update go-eth2-client to avoid crash with Lighthouse 1.0.4+
  - metric 'vouch_attestation_process_duration_seconds' now counts multiple attestations correctly
  - re-implement accountmanager metrics

1.0.2:
  - avoid crash in "best" attestationdata strategy

1.0.1:
  - include source and target epochs when scoring attestation data

1.0.0:
  - mainnet-ready
  - introduce attestation data strategy, allowing selection of best or first attestation from a set
  - used updated go-eth2-client to support current beacon node API versions
  - rework controller to schedule jobs in separate functions, allowing future flexibility
  - break accountmanager in to accountmanager, signer and validatorsmanager
    - better for maintainability and additional features
  - provide clearer log messages for submitter
  - upgrade wallet account manager to be able to accept multiple attestations to sign in a single request

0.9.0
  - use go-eth2-client for all beacon node communications
  - beacon block proposal strategy now scales per-node scores based on the distance between the slot and its parent
  - add a default process concurrency for strategies
  - fix race condition in "first" beacon block proposal strategy
  - tidy up trace logging for scheduler

0.6.2
  - do not attempt to aggregate a failed attestation
  - error appropriately when misconfigured
  - avoid crash if accountmanager not configured
  - avoid crash if beacon committee subscription information is not present
  - add measurement of validator status fetching operations
  - increase maximum block receipt delay metric from 4s to 12s
  - add internal ability to list names of all active scheduler jobs
  - ensure duplicated attestations are only counted as 1 in block proposal score
  - ensure genesis attesters are scheduled appropriately
  - do not continue if attempt to acquire a semaphore fails
  - fetch validators without balances, for (much) faster response from Prysm
  - do not fetch validator status twice on startup
  - log module selections when a choice is made

0.6.1
  - update documentation for account managers, explaining the difference between Dirk and wallet
  - add submitter configuration to documentation
  - use latest version of go-eth2-client to enable timeouts
  - if Vouch fails to obtain an updated list of validators continue with what it has
  - block proposal calculation counts slashed indices rather than slashing entries

0.6.0
  - initial release
