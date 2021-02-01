Development:
  - provide release metric in `vouch_release`
  - provide ready metric in `vouch_ready`
  - handle chain reorganisations, updating duties as appropriate
  - add `controller.max_attestation_delay` option
  - introduce aggregate attestation strategy, allowing selection of best or first aggregate attestation from a set
  - add 'epoch_slot' label to 'vouch_block_receipt_delay_seconds' metric

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
