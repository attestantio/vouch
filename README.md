Vouch is an Ethereum 2 validator focused on speed of execution for medium-to-large numbers of validators.

## Architecture

Vouch is designed with an architecture that allows each action of a validator to take place at the optimum time.


Note that there are a number of features that Vouch does not provide.  These are, in general, decisions that have been taken to keep Vouch focused on its primary role of validating.

  - key generation and wallet functions
  - user-facing metrics

  - When Vouch is started
    - Connections to beacon nodes are established
    - Signers are initialised
    - Initial state of the network is ascertained

  - When notification of a new epoch arrives
    - Beacon block proposer goroutine is spun off
    - Beacon block attester goroutine is spun off

  - When a beacon block proposer goroutine starts
    - Fetch the expected block proposals for the current epoch
    - Spin off a goroutine for each proposal for which we are responsible

  - When a beacn block proposal goroutine starts
    - Wait until appropriate time
    - Fetch details for the block
    - Create the block
    - Publish the block

  - When a chain reorganisation is notified
    - Beacon block proposer goroutine is notified
    - Beacon block attester goroutine is notified

  - When a beacn block proposer goroutine is notified of a chain reorganisation
    - Fetch the updated block proposals for the current epoch
    - Notify the relevant
