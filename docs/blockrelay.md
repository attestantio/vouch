# Block relay architecture
Vouch's block relay module acts as both an MEV-boost service and an MEV relay client.  This allows Vouch to work with both beacon nodes and MEV services to provide the best possible blocks.

## Without MEV relays
If the block relay module is configured without MEV relays it provides a subset of features.  Specifically, it will provide proposer preparations to its connected beacon nodes to ensure that any blocks proposed by validators have the correct 

### Pre-proposal preparation

### Proposing a block

## With MEV relays

 Vouch interacts with MEV relays 

Vouch acts as an MEV-boost service, which includes the following tasks:
  - sending validator registrations to remote relays
  - requesting execution payload headers from remote relays, and selecting the best one
  - providing the best execution payload header to beacon nodes
  - providing the signed blinded beacon block to the chosen remote relay, and receiving the execution payload
  - composing a full signed beacon block, and providing it to the beacon nodes


### Pre-proposal preparation
Prior to proposing blocks validators must be registered with the relay network.  This involves 

Separately, a subset(?) of the registration information must also be provided to the beacon nodes.  This ensures that the beacon nodes are aware of the validators.

Beacon nodes are configured with their builder service to use Vouch.

### Proposing a block
At the start of the slot in which one of Vouch's validators is due to propose a block, Vouch contacts all configured MEV relays and requests their bids for the best execution payload.  Once it has obtained a suitable bid it requests a blinded beacon block from all connected beacon nodes, using either the first or the best block as per the configured strategy.


Throughout the process, a failure will result in Vouch reverting to requesting a beacon block containing a local execution payload.
