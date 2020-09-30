Development
  - do not continue if attempt to acquire a semaphore fails
  - fetch validators without balances, for (much) faster response from Prysm
  - do not fetch validator status twice on startup

0.6.1
  - update documentation for account managers, explaining the difference between Dirk and wallet
  - add submitter configuration to documentation
  - use latest version of go-eth2-client to enable timeouts
  - if Vouch fails to obtain an updated list of validators continue with what it has
  - block proposal calculation counts slashed indices rather than slashing entries

0.6.0
  - initial release
