# Configuration
Vouch can be configured through environment, command-line or configuration file.  In the case of conflicting configuration the order of precedence is:

  - command-line; then
  - environment; then
  - configuration file.

# The configuration file
Vouch's configuration file can be written in JSON or YAML.  The file can either be in the user's home directory, in which case it will be called `.vouch.json` (or `.vouch.yml`), or it can be in a directory specified by the command line option `--base-dir` or environment variable `VOUCH_BASE_DIR`, in which case it will be called `vouch.json` (or `vouch.yml`).

A sample configuration file in YAML with is shown below:

```YAML
# log-file is the location for Vouch log output.  If this is not provided logs will be written to the console.
log-file: /home/me/vouch.log
# log-level is the global log level for Vouch logging.
# Overrides can be set at any sub-level, giving fine-grained control over the specific
# information logged.
log-level: 'debug'

logging:
  timestamp:
    # format defines the format of the timestamp in the log.  This can be any valid Go timestamp formatting string,
    # or the special values '', 'UNIXMS', 'UNIXMICRO' or 'UNIXNANO' for Unix timestamps of varying precision.
    format: '2006-01-02T15:04:05.999Z07:00'

# beacon-node-address is the address of the beacon node.  Can be lighthouse, nimbus, prysm or teku.
# Overridden by beacon-node-addresses if present.
beacon-node-address: 'localhost:4000'

# beacon-node-addresses is the list of address of the beacon nodes.  Can be lighthouse, nimbus, prysm or teku.
# If multiple addresses are supplied here it makes Vouch resilient in the situation where a beacon
# node goes offline entirely.  If this occurs to the currently used node then the next in the list will
# be used.  If a beacon node comes back online it is added to the end of the list of potential nodes to
# use.
#
# Note that some beacon nodes have slightly different behavior in their events.  As such, users should
# ensure they are happy with the event output of all beacon nodes in this list.
beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']

# timeout is the timeout for all validating operations, for example fetching attestation data from beacon nodes.
timeout: '2s'

# reduced-memory-usage can be set on memory-constrained systems to reduce memory usage, at the cost of increased processing time.
reduced-memory-usage: false

eth2client:
  # timeout is the timeout for all operations against beacon nodes that are not related to a specific validating
  # operation, for example fetching the current list of active validators.  These operations are not time-sensitive,
  # and can contain large amounts of information, hence the longer timeout.
  timeout: '2m'
  #
  # allow-delayed-start allows Vouch to start if some of the consensus nodes are unavailable.
  # Note that this can result in Vouch being active without being able to validate, however, if strategies use
  # a subset of beacon nodes that are all unavailable.
  allow-delayed-start: true

# metrics is the module that logs metrics, in this case using prometheus.
metrics:
  prometheus:
    # log-level is the log level for this module, over-riding the global level.
    log-level: 'warn'
    # listen-address is the address on which prometheus listens for metrics requests.
    listen-address: '0.0.0.0:8081'

# graffiti provides graffiti data.  Full details are in the separate document.
graffiti:
  static:
    value: 'My graffiti'

# controller controls when validating actions take place.
controller:
  fast-track: 
    # If attestations is true then Vouch will attest as soon as it receives notification that the head block has been updated
    # for the duties' slot.  Otherwise it will wait until 4 seconds into the slot before attesting.
    attestations: true
    # If sync-committees is true then Vouch will generate sync committee messages as soon as it receives notification that
    # the head block has been updated for the duties' slot.  Otherwise it will wait until 4 seconds into the slot before
    # generating sync committee messages.
    sync-committees: true
    # grace is the delay between receiving the notification of the head block and starting the fast track process.  This allows
    # the rest of the network to settle if we saw the head block early.
    grace: '200ms'
  # This flag enables verification of sync committee messages included in SyncAggregate. Exposes information via metrics and logs, 
  # defaults to false as this requires some extra processing to calculate the required metrics.
  verify-sync-committee-inclusion: false

# beaconblockproposer provides control of the beacon block proposal process.
beaconblockproposer:
  # If unblind-from-all-relays is true then Vouch will use all relays that it asked for blocks to unblind the
  # selected bid.  This can potentially increase the reliability of obtaining an unblinded block, but will increment
  # failures in the eth_builder_client_operations_total metric for the relays that do not know of the bid.
  unblind-from-all-relays: false
  # builder-boost-factor provides relative weightings between locally-produced and relay-supplied execution payloads.
  # See https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/produceBlockV3 for full details, but some sample
  # values are:
  # -  50: `builder value` must be more than twice the local value (`local value*(100/50)`) to be used
  # -  91: `builder value` must be more than ~10% higher than the local value (`local value*(100/91)`) to be used
  # - 100: `builder value` must be more than the local value (`local value*(100/100)`) to be used
  builder-boost-factor: 91

# submitter submits data to beacon nodes.  If not present the nodes in beacon-node-address above will be used.
submitter:
  # style can currently only be 'multinode'
  style: 'multinode'
  aggregateattestation:
    # beacon-node-addresses are the addresses to which to submit aggregate attestations.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  attestation:
    # beacon-node-addresses are the addresses to which to submit attestations.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  beaconcommitteesubscription:
    # beacon-node-addresses are the addresses to which to submit beacon committee subscriptions.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  proposal:
    # beacon-node-addresses are the addresses to which to submit beacon block proposals.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  proposalpreparation:
    # beacon-node-addresses are the addresses to which to submit beacon proposal preparations.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  synccommitteecontribution:
    # beacon-node-addresses are the addresses to which to submit beacon sync committee contributions.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  synccommitteemessage:
    # beacon-node-addresses are the addresses to which to submit beacon sync committee messages.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  synccommitteesubscription:
    # beacon-node-addresses are the addresses to which to submit beacon sync committee subscriptions.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']

# strategies provide advanced strategies for dealing with multiple beacon nodes
strategies:
  # The attestationdata strategy obtains attestation data from multiple sources.
  attestationdata:
    # style can be 'best', which obtains attestation data from all nodes and selects the best, 'first', which uses the first returned,
    # or 'majority', which obtains attestation data from all nodes and selects the most common.
    style: 'best'
    # beacon-node-addresses are the addresses from which to receive attestation data.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
    majority:
      # threshold is the minimum number of beacon nodes that have to provide the same attestation data for Vouch with the 'majority'
      # strategy to use it.
      threshold: 2
  # The aggregateattestation strategy obtains aggregate attestations from multiple sources.
  # Note that the list of nodes here must be a subset of those in the attestationdata strategy.  If not, the nodes will not have
  # been gathering the attestations to aggregate and will error when the aggregate request is made.
  aggregateattestation:
    # style can be 'best', which obtains aggregates from all nodes and selects the best, or 'first', which uses the first returned
    style: 'best'
    # beacon-node-addresses are the addresses from which to receive aggregate attestations.
    # Note that prysm nodes are not supported at current in this strategy.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
  # The beaconblockproposal strategy obtains beacon block proposals from multiple beacon nodes.
  beaconblockproposal:
    # style can be 'best', which obtains blocks from all nodes and selects the best, or 'first', which uses the first returned
    style: 'best'
    # beacon-node-addresses are the addresses from which to receive beacon block proposals.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
    # timeout defines the maximum amount of time the strategy will wait for a response.  As soon as a response from all beacon
    # nodes has been obtained,the strategy will return with the best.  Half-way through the timeout period, Vouch will check to see
    # if there have been any responses from the beacon nodes, and if so will return with the best.
    # This allows Vouch to remain responsive in the situation where some beacon nodes are significantly slower than others, for
    # example if one is remote.
    timeout: '2s'
  # The beaconblockheader strategy obtains the beacon block headers from multiple beacon nodes.
  beaconblockheader:
    # style can be 'first'. If not defined or set to another value Vouch will default to using the multiclient.
    style: 'first'
    first:
      # beacon-node-addresses are the addresses from which to receive beacon block headers.
      beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
      # timeout defines the maximum amount of time the strategy will wait for a response.  Different strategies may return earlier
      # if they have obtained enough information from their beacon node(s).
      timeout: '2s'
  # The beaconblockroot strategy obtains the beacon block root from multiple beacon nodes.
  beaconblockroot:
    # style can be 'first', which uses the first returned, 'latest', which uses the latest returned, or 'majority', which uses
    # the one returned by most nodes (taking the latest in case of a tie).
    style: 'latest'
    # beacon-node-addresses are the addresses from which to receive beacon block roots.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
    # timeout defines the maximum amount of time the strategy will wait for a response.  Different strategies may return earlier
    # if they have obtained enough information from their beacon node(s).
    timeout: '2s'
  builderbid:
    # style can be 'best', which uses the best bid returned from a single request to each of the configured relays, or 'deadline',
    # which repeatedly queries the configured relays until the deadline is reached.
    style: 'best'
    best:
      # timeout defines the maximum amount of time that Vouch will wait for relays to respond.
      timeout: '2s'
    deadline:
      # deadline defines the maximum amount of time that Vouch will query relays before stopping.
      deadline: '1s'
      # bid-gap is the gap between receiving a response from a relay and querying it again.
      bid-gap: '100ms'
  # The signedbeaconblock strategy obtains the signed beacon blocks from multiple beacon nodes.
  signedbeaconblock:
    # style can be 'first'. If not defined or set to another value Vouch will default to using the multiclient.
    style: 'first'
    first:
      # beacon-node-addresses are the addresses from which to receive signed beacon blocks.
      beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']
      # timeout defines the maximum amount of time the strategy will wait for a response.  Different strategies may return earlier
      # if they have obtained enough information from their beacon node(s).
      timeout: '2s'
  # The synccommitteecontribution strategy obtains sync committee contributions from multiple sources.
  synccommitteecontribution:
    # style can be 'best', which obtains contributions from all nodes and selects the best, or 'first', which uses the first returned
    style: 'best'
    # beacon-node-addresses are the addresses from which to receive sync committee contributions.
    beacon-node-addresses: ['localhost:4000', 'localhost:5051', 'localhost:5052']

# blockrelay provides information about working with local execution clients and remote relays for block proposals.
blockrelay:
  # config is a URL that contains the configuration file for carrying out auctions.  Each validator can have a different
  # set of relays, a different fee recipient, and a different gas limit if required.  Details about the format of this file
  # can be found in the "Execution configuration" document.
  config:
    url: 'file:///home/vouch/config.json'
  # fallback-fee-recipient is used for validators that do not have a value provided by the configuration above.
  fallback-fee-recipient: '0x0000000000000000000000000000000000000001'
  # fallback-gas-limit is used for validators that do not have a value provided by the configuration above.
  fallback-gas-limit: 30000000
  # If log-results is true then the results of each block auction will be written to the logs.  Output will include each
  # participating relay, the bid provided, and if the bid was selected for use by Vouch.
  log-results: true
  # builder-configs contain specific configurations for different builders, with each builder defined by its public key.
  # The base score for each bid is the value to the proposer, in wei.  The final score is calculated by adding
  # the 'offset' value for the specific builder, and then multiplying by the percentage of 'factor' value. For example,
  # if the base value is 1000, the offset is 10 and the factor is 110 then the final score is (1000+10)*110/100 = 1111.  If the
  # offset is not configured it defaults to 0; if the factor is not configured it defaults to 100.  The category is used
  # for differentiation of bids in metrics.
  builder-configs:
    '0xaaaa...':
      category: 'privileged'
      # With factor of 1000000000 bids from this builder are pretty much guaranteed to be included above bids from other builders.
      factor: 1000000000
    '0xbbbb...':
      category: 'excluded'
      # With a factor of 0 bids from this builder will be ignored.
      factor: 0

# tracing sends OTLP trace data to the supplied endpoint.
tracing:
  # Address is the host and port of an OTLP trace receiver.
  address: 'server:4317'
  # If the endpoint is secure you will need to supply a client certificate and key, and optionally a CA certificate if your client
  # certificate is issued by a private certificate authority.
  client-cert: 'file:///home/vouch/certs/server.crt'
  client-key: 'file:///home/vouch/certs/server.key'
  ca-cert: 'file:///home/vouch/certs/ca.crt'
```

## Hierarchical configuration.
A number of items in the configuration are hierarchical.  If not stated explicitly at a point in the configuration file, Vouch will move up the levels of configuration to attempt to find the relevant information.  For example, when searching for the value `submitter.attestation.multinode.beacon-node-addresses` the following points in the configuration will be checked:

  - `submitter.attestation.multinode.beacon-node-addresses`
  - `submitter.attestation.beacon-node-addresses`
  - `submitter.beacon-node-addresses`
  - `beacon-node-addresses`

Vouch will use the first value obtained.  Continuing the example, if a configuration file is set up as follows:

```YAML
beacon-node-addresses: [ 'localhost:4000', 'localhost:5051' ]
strategies:
  beacon-node-address: [ 'localhost:5051' ]
  beaconblockproposal:
    style: 'best'
    beacon-node-addresses: [ 'localhost:4000' ]
submitter:
  style: 'multinode'
  proposal:
    multinode:
      beacon-node-addresses: ['localhost:4000', 'localhost:9000']
```

Then the configuration will resolve as follows:
  - `beacon-node-addresses` resolves to `['localhost:4000', 'localhost:5051']` with a direct match
  - `strategies.attestationdata.best.beacon-node-addresses` resolves `['localhost:5051']` at `strategies.beacon-node-addresses`
  - `strategies.beaconblockproposal.best.beacon-node-addresses` resolves `['localhost:4000']` at `strategies.beacon-node-addresses`
  - `submitter.proposal.multinode.beacon-node-addresses` resolves `['localhost:4000', 'localhost:9000']` with a direct match
  - `submitter.attestation.multinode.beacon-node-addresses` resolves `['localhost:4000', 'localhost:5051']` at `beacon-node-addresses`

Hierarchical configuration provides a simple way of setting defaults and overrides, and is available for `beacon-node-addresses`, `log-level`, `timeout` and `process-concurrency` configuration values.

## Logging
Vouch has a modular logging system that allows different modules to log at different levels.  The available log levels are:

  - **Fatal**: messages that result in Vouch stopping immediately;
  - **Error**: messages due to Vouch being unable to fulfil a valid process;
  - **Warning**: messages that result in Vouch not completing a process due to transient or user issues;
  - **Information**: messages that are part of Vouch's normal startup and shutdown process;
  - **Debug**: messages when one of Vouch's processes diverge from normal operations;
  - **Trace**: messages that detail the flow of Vouch's normal operations; or
  - **None**: no messages are written.

### Global level
The global level is used for all modules that do not have an explicit log level.  This can be configured using the command line option `--log-level`, the environment variable `VOUCH_LOG_LEVEL` or the configuration option `log-level`.

### Module levels
Modules levels are used for each module, overriding the global log level.  The available modules are:

  - **accountmanager** access to validating accounts
  - **attestationaggregator** aggregating attestations
  - **attester** attesting to blocks
  - **beaconcommitteesubscriber** subscribing to beacon committees
  - **beaconblockproposer** proposing beacon blocks
  - **chaintime** calculations for time on the blockchain (start of slot, first slot in an epoch _etc._)
  - **controller** control of which jobs occur when
  - **graffiti** provision of graffiti for proposed blocks
  - **majordomo** accesss to secrets
  - **scheduler** starting internal jobs such as proposing a block at the appropriate time
  - **signer** carries out signing activities
  - **strategies.attestationdata** decisions on how to obtain information from multiple beacon nodes
  - **strategies.aggregateattestation** decisions on how to obtain information from multiple beacon nodes
  - **strategies.beaconblockproposal** decisions on how to obtain information from multiple beacon nodes
  - **strategies.synccommitteecontribution** decisions on how to obtain information from multiple beacon nodes
  - **submitter** decisions on how to submit information to multiple beacon nodes
  - **validatorsmanager** obtaining validator state from beacon nodes and providing it to other modules

This can be configured using the environment variables `VOUCH_<MODULE>_LOG_LEVEL` or the configuration option `<module>.log-level`.  For example, the controller module logging could be configured using the environment variable `VOUCH_CONTROLLER_LOG_LEVEL` or the configuration option `controller.log-level`.

## Advanced options
Advanced options can change the performance of Vouch to be severely detrimental to its operation.  It is strongly recommended that these options are not changed unless the user understands completely what they do and their possible performance impact.

### controller.max-attestation-delay
This is a duration parameter, that defaults to `4s`.  It defines the maximum time that Vouch will wait from the start of a slot for a block before attesting on the basis that the slot is empty.

### controller.attestation-aggregation-delay
This is a duration parameter, that defaults to `8s`.  It defines the time that Vouch will wait from the start of a slot before aggregating existing attestations.

### controller.max-sync-committee-message-delay
This is a duration parameter, that defaults to `4s`.  It defines the maximum time that Vouch will wait from the start of a slot for a block before generating sync committee messages on the basis that the slot is empty.

### controller.sync-committee-aggregation-delay
This is a duration parameter, that defaults to `8s`.  It defines the time that Vouch will wait from the start of a slot before aggregating existing sync committee messages.
