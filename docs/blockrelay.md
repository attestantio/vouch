# Block relay
Maximal extractable value

Vouch acts as an MEV-boost service, which includes the following tasks:
  - sending validator registrations to remote relays
  - requesting execution payload headers from remote relays, and selecting the best one
  - providing the best execution payload header to beacon nodes
  - providing the signed blinded beacon block to the chosen remote relay, and receiving the execution payload
  - composing a full signed beacon block, and providing it to the beacon nodes

## Block relay configuration and options

The minimal configuration for the block relay is as follows:

```
blockrelay:
  fallback-fee-recipient: '0x0123...cdef'
```

This will use the provided address `0x0123...cdef` as the fee recipient for all beacon block proposals.

Where the `listen-address` is the address on which the block relay will listen, and `url` is the path to a local file that contains the proposer configuration as per TODO the specification.

For more dynamic environments it is possible to fetch the proposer configuration from a remote URL, for example:

```
blockrelay:
  config:
    url: 'http://example.com/proposerconfig'
```

would attempt to fetch the file at `http://example.com/proposerconfig` and use that.  To aid server processes that serve this information the request is a POST with a body containing a list of the public keys for which Vouch expects to validate in the next epoch.

The proposer configuration is fetched on startup and refetched every epoch to ensure that it remains up-to-date with any changes that are made.

## Interaction between block relay and fee recipient modules
