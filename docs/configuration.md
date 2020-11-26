# Configuration
Vouch can be configured through environment, command-line or configuration file.  In the case of conflicting configuration the order of precedence is:

  - command-line; then
  - environment; then
  - configuration file.

# The configuration file
Vouch's configuration file can be written in JSON or YAML.  The file can either be in the user's home directory, in which case it will be called `.vouch.json` (or `.vouch.yml`), or it can be in a directory specified by the command line option `--base-dir` or environment variable `VOUCH_BASE_DIR`, in which case it will be called `vouch.json` (or `vouch.yml`).

A sample configuration file in YAML with is shown below:

```
# log-file is the location for Vouch log output.  If this is not provided logs will be written to the console.
log-file: /home/me/vouch.log
# log-level is the global log level for Vouch logging.
log-level: Debug

# beacon-node-address is the address of the beacon node.  Can be prysm, lighthouse, teku
beacon-node-address: localhost:4000

# metrics is the module that logs metrics, in this case using prometheus.
metrics:
  prometheus:
    # log-level is the log level for this module, over-riding the global level.
    log-level: warn
    # listen-address is the address on which prometheus listens for metrics requests.
    listen-address: 0.0.0.0:8081

# graffiti provides graffiti data.  Full details are in the separate document.
graffiti:
  static:
    value: My graffiti

# submitter submits data to beacon nodes.  If not present the nodes in beacon-node-address above will be used.
submitter:
  # style can currently only be 'all'
  style: all
  # beacon-node-addresses is the list of addresses to which submit.  Submissions run in parallel
  beacon-node-addresses:
    - localhost:4000
    - localhost:5051
    - localhost:5052

# strategies provide advanced strategies for dealing with multiple beacon nodes
strategies:
  # The beaconblockproposal strategy obtains beacon block proposals from multiple sources.
  beaconblockproposal:
    # style can be 'best', which obtains blocks from all nodes and selects the best, or 'first', which uses the first returned
    style: best
    # beacon-node-addresses are the addresses of beacon nodes to use for this strategy.
    beacon-node-addresses:
      - localhost:4000
      - localhost:5051
      - localhost:5052
  # The attestationdata strategy obtains attestation data from multiple sources.
  attestationdata:
    # style can be 'best', which obtains attestations from all nodes and selects the best, or 'first', which uses the first returned
    style: best
    # beacon-node-addresses are the addresses of beacon nodes to use for this strategy.
    beacon-node-addresses:
      - localhost:4000
      - localhost:5051
      - localhost:5052
```

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
  - **strategies.beaconblockproposer** decisions on how to obtain information from multiple beacon nodes
  - **submitter** decisions on how to submit information to multiple beacon nodes
  - **validatorsmanager** obtaining validator state from beacon nodes and providing it to other modules

This can be configured using the environment variables `VOUCH_<MODULE>_LOG_LEVEL` or the configuration option `<module>.log-level`.  For example, the controller module logging could be configured using the environment variable `VOUCH_CONTROLLER_LOG_LEVEL` or the configuration option `controller.log-level`.
