Development:
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
