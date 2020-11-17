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
