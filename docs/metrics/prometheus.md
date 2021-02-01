# Prometheus metrics
vouch provides a number of metrics to check the health and performance of its activities.  vouch's default implementation uses Prometheus to provide these metrics.  The metrics server listens on the address provided by the `metrics.address` configuration value.

## Version
The version of Vouch can be found in the `vouch_release` metric, in the `version` label.

## Health
Health metrics provide a mechanism to confirm if vouch is active.  Due to vouch's nature there are multiple metrics that can be used to provide health and activity information that can be monitored.

`vouch_start_time_secs` is the Unix timestamp at which vouch was started.  This value will remain the same throughout a run of vouch; if it increments it implies that vouch has restarted.

`vouch_ready` is `1` if Vouch's services are all on-line and it is able to operate.  If not, this will be `0`.

`vouch_epochs_processed_total` the number of epochs vouch has processed.  This number resets to 0 when vouch restarts, and increments every time vouch starts to process an epoch; if it fails to increment it implies that vouch has stopped processing.

`vouch_accountmanager_accounts_total` is the number of accounts for which vouch is validating.  This metric has one label, `state`, which can take one of the following values:
  - `unknown` the validator is not known to the Ethereum 2 network
  - `pending_initialized` the validator is known to the Ethereum 2 network but not yet in the queue to be activated
  - `pending_queued` the validator is in the queue to be activated
  - `active_ongoing` the validator is active
  - `active_exiting` the validator is active but stopping its duties
  - `exited_unslashed` the validator has exited without being slashed
  - `exited_slashed` the validator has exited after being slashed
  - `withdrawal_possible` the validator's funds are applicable for withdrawal (although withdrawal is not possible in phase 0)

Vouch will attest for accounts that are either `active_ongoing` or `active_exiting`.  Any increase in `active_exiting` should be matched with valid exit requests.  Any increase in `active_slashed` suggests a problem with the validator setup that should be investigated as a matter of urgency.

There are also counts for each process.  The specific metrics are:

  - `vouch_beaconblockproposal_process_requests_total` number of beacon block proposal processes;
  - `vouch_attestation_process_requests_total` number of attestation processes;
  - `vouch_beaconcommitteesubscription_process_requests_total` number of beacon committee subscription processes; and
  - `vouch_attestationaggregation_process_failure_total` number of attestation aggregation processes.

All of the metrics have the label "result" with the value either "succeeded" or "failed2.  Any increase in the latter values implies the validator is not completing all of its activities, and should be investigated.

## Performance
Performance metrics provide a mechanism to understand how quickly vouch is carrying out its activities.  The following information is provided:

  - `vouch_beaconblockproposal_process_duration_seconds` time taken to carry out the beacon block proposal process;
  - `vouch_attestation_process_duration_seconds` time taken to carry out the attestation process;
  - `vouch_beaconcommitteesubscription_process_duration_seconds` time taken to carry out the beacon committee subscription process; and
  - `vouch_attestationaggregation_process_duration_seconds` time taken to carry out the attestation aggregation process.

These metrics are provided as histograms, with buckets in increments of 0.1 seconds up to 1 second.

## Operations
Operations metrics provide information about numbers of operations performed.  These are generally lower-level information that can be useful to monitor activities for fine-tuning of server parameters, comparing one instance to another, _etc._

Vouch's job scheduler provides a number of metrics.  The specific metrics are:

  - `vouch_scheduler_jobs_scheduled_total` number of jobs scheduled;
  - `vouch_scheduler_jobs_cancelled_total` number of jobs cancelled; and
  - `vouch_scheduler_jobs_started_total` number of jobs started.  This has a label `trigger` which can be "timer" if the job ran due to reaching its designated start time or "signal" if the job ran due to being triggered before its designated start time.

## Client operations
Client operations metrics provide information about the response time of beacon nodes, as well as if the request to them succeeded or failed.  This can be used to understand how quickly and how well beacon nodes are responding to requests, for example if Vouch using multiple beacon nodes in different data centres this can be used to obtain data about their response times due to network latency.

`vouch_client_opeation_duration_seconds` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It has two labels:

  - `proposer` is the endpoint for the operation
  - `operation` is the operation that took place (_e.g._ "beacon block proposal")

There is also a companion metric `vouch_client_operation_requests_total`, which is a simple count of the number of operations that have taken place.  It has three labels:

  - `proposer` is the endpoint for the operation
  - `operation` is the operation that took place (_e.g._ "beacon block proposal")
  - `result` is the result of the operation, either "succeeded" or "failed"

## Network
Network metrics provide information about the network from vouch's point of view.  Although these are not under vouch's control, they have an impact on the performance of the validator.  The specific metrics are:

  - `vouch_block_receipt_delay_seconds` the delay between the start of a slot and the arrival of the block for that slot.  This metric is provided as a histogram, with buckets in increments of 0.1 seconds up to 12 seconds.  This has a label `epoch_slot` which is the position of the slot in the epoch (0 through 31, inclusive).
  - `vouch_attestationaggregation_coverage_ratio` the ratio of the number of attestations included in the aggregate to the total number of attestations for the aggregate.  This metric is provided as a histogram, with buckets in increments of 0.1 up to 1.
