# Prometheus metrics
Vouch provides comprehensive metrics to check the health and performance of its activities.  This document describes the metrics available for Prometheus and similar monitoring systems.

The metrics server listens on the address provided by the `metrics.address` configuration value, and makes metrics available at the `/metrics` endpoint.

## General information

There are a number of metrics that provide general information about Vouch.  Specifically:

  - `vouch_release` contains the version of Vouch, in the `version` label
  - `vouch_ready` is set to `1` when Vouch is ready to start attesting, and `0` otherwise.  If this number stays at 0 it implies a configuration or connection issue that should be addressed
  - `vouch_epochs_processed_total` is set to the number of epochs for which Vouch has been attesting.  This number resets to 0 when Vouch restarts, and increments every time Vouch starts to process an epoch; if it fails to increment it implies that Vouch has stopped processing
  - `vouch_start_time_secs` is the unix timestamp of the time that Vouch started.  This value will remain the same throughout a run of Vouch; if it increments it implies that Vouch has restarted.

In addition, high level metrics track the latest slot for which Vouch carried out a successful operation:

  - `vouch_attestation_process_latest_slot` the latest slot for which Vouch carried out an attestation.  As long as Vouch has validators, this is expected to increment approximately every 6.5 minutes, although it is possible to have to wait up to 13 minutes due to the random assignment of slots to validators
  - `vouch_attestationaggregation_process_latest_slot` the latest slot for which Vouch carried out an attestation aggregation.  This is a relatively infrequent occurrence
  - `vouch_beaconblockproposal_process_latest_slot` the latest slot for which Vouch carried out a proposal.  This is a relatively infrequent occurrence
  - `vouch_synccommitteeaggregation_process_latest_slot` the latest slot for which Vouch carried out a sync committee aggregation.  This is a very infrequent occurrence
  - `vouch_synccommitteemessage_process_latest_slot` the latest slot for which Vouch generated a sync committee message.  This is a very infrequent occurrence

There are also counts for each process.  The specific metrics are:

  - `vouch_beaconblockproposal_process_requests_total` number of beacon block proposal processes;
  - `vouch_attestation_process_requests_total` number of attestation processes;
  - `vouch_beaconcommitteesubscription_process_requests_total` number of beacon committee subscription processes; and
  - `vouch_attestationaggregation_process_requests_total` number of attestation aggregation processes.

All of the metrics have the label "result" with the value either "succeeded" or "failed".  Any increase in the latter values implies the validator is not completing all of its activities, and should be investigated.

## Accounts

Vouch keeps track of the number of accounts for which it is validating in the `vouch_accountmanager_accounts_total` metric.  This metric has one label, `state`, which can take one of the following values:

  - `unknown` the validator is not known to the Ethereum 2 network
  - `pending_initialized` the validator is known to the Ethereum 2 network but not yet in the queue to be activated
  - `pending_queued` the validator is in the queue to be activated
  - `active_ongoing` the validator is active
  - `active_exiting` the validator is active but stopping its duties
  - `exited_unslashed` the validator has exited without being slashed
  - `exited_slashed` the validator has exited after being slashed
  - `withdrawal_possible` the validator's funds are applicable for withdrawal (although withdrawal is not possible in phase 0)

Vouch will attest for accounts that are either `active_ongoing` or `active_exiting`.  Any increase in `active_exiting` should be matched with valid exit requests.  Any increase in `active_slashed` suggests a problem with the validator setup that should be investigated as a matter of urgency.

## Marks

Vouch uses marks to show the point in time within a slot at which it completes its various operations.  The mark is made after the operation has submitted any results of its work to its beacon nodes, and so can be used to confirm that Vouch is acting in a timely fashion.  Each mark is a histogram from 0 to 12 seconds, in 0.1 second increments.  The marks are as follows:

  - `vouch_attestation_mark_seconds` is the time in the slot at which the attestation(s) for the slot have been submitted to the beacon nodes.  In a healthy network it would be expected that the majority of these would be before the 6 second mark.  Any significant number of these after the 7 second mark suggests that part of the validating infrastructure may be slow, and should be investigated
  - `vouch_beaconblockproposal_mark_seconds` is the time in the slot at which the block for the slot has been submitted to the beacon nodes.  In a healthy network it would be expected that the majority of these would be before the 1 second mark.  Any significant number of these after the 2 second mark suggests that part of the validating infrastructure may be slow, and should be investigated
  - `vouch_synccommitteemessage_mark_seconds` is the time in the slot at which the sync committee message(s) for the slot has been submitted to the beacon nodes.  In a healthy network it would be expected that the majority of these would be before the 6 second mark.  Any significant number of these after the 7 second mark suggests that part of the validating infrastructure may be slow, and should be investigated
  - `vouch_attestationaggregation_mark_seconds` is the time in the slot at which attestation aggregation message(s) for the slot has been submitted to the beacon nodes.  In a healthy network it would be expected that the majority of these would be before the 9 second mark.  Any significant number of these after the 10 second mark suggests that part of the validating infrastructure may be slow, and should be investigated.  It would also be expected that all of these message would be after the 8 second mark.  Any number of these before the 8 second mark suggests a problem with system time, and should be investigated
  - `vouch_synccommitteeaggregation_mark_seconds` is the time in the slot at which sync committee aggregation message(s) for the slot has been submitted to the beacon nodes.  In a healthy network it would be expected that the majority of these would be before the 9 second mark.  Any significant number of these after the 10 second mark suggests that part of the validating infrastructure may be slow, and should be investigated.  It would also be expected that all of these message would be after the 8 second mark.  Any number of these before the 8 second mark suggests a problem with system time, and should be investigated

## Performance
Performance metrics provide a mechanism to understand how quickly Vouch is carrying out its activities.  The following information is provided:

  - `vouch_attestation_process_duration_seconds` time taken to carry out the attestation process
  - `vouch_attestationaggregation_process_duration_seconds` time taken to carry out the attestation aggregation process
  - `vouch_beaconblockproposal_process_duration_seconds` time taken to carry out the beacon block proposal process
  - `vouch_beaconcommitteesubscription_process_duration_seconds` time taken to carry out the beacon committee subscription process
  - `vouch_synccommitteeaggregation_process_duration_seconds` time taken to carry out the sync committee aggregation process
  - `vouch_synccommitteemessage_process_duration_seconds` time taken to carry out the sync committee message process
  - `vouch_synccommitteesubscription_process_duration_seconds` time taken to carry out the sync committee subscription process

These metrics are provided as histograms, with buckets in increments of 0.1 seconds up to 2 seconds.

A major part of Vouch's work is in the strategy section, where it selects the appropriate data to sign.  Data that combines the provider of the data along with the time taken to obtain and evaluate it contained in the `vouch_strategy_operation_duration_seconds` metric.  This is a histogram with buckets in increments of 0.1 seconds up to 4 seconds.  It has three labels:

  - `strategy` is the strategy for the operation
  - `provider` is the provider for the operation
  - `operation` is the operation that took place (_e.g._ "beacon block proposal")

## Operations
Operations metrics provide information about Vouch's internal operations.  These are generally lower-level information that can be useful to monitor activities for fine-tuning of server parameters, comparing one instance to another, _etc._

Vouch's job scheduler provides a number of metrics.  The specific metrics are:

  - `vouch_scheduler_jobs_scheduled_total` number of jobs scheduled.  This is expected to increment periodically throughout Vouch's runtime
  - `vouch_scheduler_jobs_cancelled_total` number of jobs cancelled.  This increments when chain reorganizations occur, and pre-scheduled jobs are no longer valid
  - `vouch_scheduler_jobs_started_total` number of jobs started.  This has a label `trigger` which can be "timer" if the job ran due to reaching its designated start time or "signal" if the job ran due to being triggered before its designated start time

Each of the above metrics also has a `class` label which defines the general class of the job running.  Possible values include:
  - `Aggregate attestations` jobs relating to aggregating attestations
  - `Aggregate sync committee messages` jobs relating to aggregating sync committee messages
  - `Attest` jobs relating to attesting
  - `Epoch` jobs relating to operations run in preparation for or at the start of epochs
  - `Generate sync committee messages` jobs relating to generating sync committee messages
  - `Prepare for sync committee messages` jobs relating to preparation of sync committee message generation
  - `Propose` jobs relating to proposing blocks
  - `Refresh accounts` jobs relating to updating internal account information

Client operations metrics provide information about the response time of beacon nodes, as well as if the request to them succeeded or failed.  This can be used to understand how quickly and how well beacon nodes are responding to requests, for example if Vouch using multiple beacon nodes in different data centres this can be used to obtain data about their response times due to network latency.

`vouch_client_operation_duration_seconds` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It has two labels:

  - `proposer` is the endpoint for the operation
  - `operation` is the operation that took place (_e.g._ "beacon block proposal")

There is also a companion metric `vouch_client_operation_requests_total`, which is a simple count of the number of operations that have taken place.  It has three labels:

  - `proposer` is the endpoint for the operation
  - `operation` is the operation that took place (_e.g._ "beacon block proposal")
  - `result` is the result of the operation, either "succeeded" or "failed"

`vouch_strategy_operation_used` provides details of the outcome of strategies, where one piece of data is obtained from a number of providers.  It has three labels:

  - `operation` is the operation that took place (_e.g._ "beacon block proposal")
  - `provider` is the provider of the information selected by the strategy
  - `strategy` is the strategy used to select the outcome

Network metrics provide information about the network from Vouch's point of view.  Although these are not under Vouch's control, they have an impact on the performance of the validator.  The specific metrics are:

  - `vouch_block_receipt_delay_seconds` the delay between the start of a slot and the arrival of the block for that slot.  This metric is provided as a histogram, with buckets in increments of 0.1 seconds up to 12 seconds.  This has a label `epoch_slot` which is the position of the slot in the epoch (0 through 31, inclusive)
  - `vouch_attestationaggregation_coverage_ratio` the ratio of the number of attestations included in the aggregate to the total number of attestations for the aggregate.  This metric is provided as a histogram, with buckets in increments of 0.1 up to 1.
  - `vouch_synccommitteeaggregation_coverage_ratio` the ratio of the number of sync committee messages included in the aggregate to the total number of members of the sync committee for the aggregate.  This metric is provided as a histogram, with buckets in increments of 0.1 up to 1.

## Relay
Relay metrics provide information about the performance, both individually and comparatively, of the block relays configured for use.

`vouch_relay_auction_block_duration_seconds` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It provides details of the total time taken for Vouch to obtain the best bid from competing relays.  There is also a companion metric `vouch_relay_auction_block_duration_seconds_count`, which is a simple count of the number of operations that have taken place.

`vouch_relay_auction_block_used_total` provides the number of blocks used.  It has two labels:

  - `provider` is the address of the relay used from which the winning bid comes
  - `category` is the categorization of the builder from which the winning bid comes.  This is free-form text, and supplied by the user in the builder confguration (defaults to "standard" if no category is supplied)

`vouch_relay_builder_bid_delta_meth_bucket` is provided as a histogram, with buckets in increments of 10 milliEther up to 1 Ether.  It provides details of the difference in value between the winning bid and the bid from the given provider. It has a single label:

  - `provider` is the address of the relay used from which a losing bid comes

There is also a companion metric `vouch_relay_auction_block_duration_seconds_count`, which is a simple count of the number of operations that have taken place.

`vouch_relay_builder_bid_duration_seconds_bucket` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It provides details of the total time taken for Vouch to serve builder bid requests from beacon nodes.  There is also a companion metric `vouch_relay_builder_bid_duration_seconds_count`, which is a simple count of the number of operations that have taken place.

`vouch_relay_execution_config_duration_seconds_bucket` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It provides details of the total time taken for Vouch to obtain the execution configuration from the local or remote source.  There is also a companion metric `vouch_relay_execution_config_duration_seconds_count`, which is a simple count of the number of operations that have taken place.

`vouch_relay_validator_registrations_duration_seconds_bucket` is provided as a histogram, with buckets in increments of 0.1 seconds up to 4 seconds.  It provides details of the total time taken for Vouch to serve validator registration requests from beacon nodes.  There is also a companion metric `vouch_relay_validator_registrations_duration_seconds_count`, which is a simple count of the number of operations that have taken place.

## Sync Committee Verification

Sync Committee Verification metrics can be enabled using the `controller.verify-sync-committee-inclusion` flag in the configuration. This gives more insight in to the participation of Sync Committee duties:

- `vouch_synccommitteeverification_current_assigned` is a gauge that is set to the current number of vouch validators that are participating in Sync Committee duty.
- `vouch_synccommitteeverification_mismatches_total` is a counter that increments each time vouch receives a head event where the parent block root does not match the root vouch broadcast in the Sync Committee messages. 
- `vouch_synccommitteeverification_found_total` is a counter that increments for each vouch validator that has been included in the SyncAggregate. This is not incremented if we already detected a root mismatch or if we didn't record the Sync Committee head (expected after a restart)
- `vouch_synccommitteeverification_missing_total` is a counter that increments for each vouch validator that has NOT been included in the SyncAggregate. This is not incremented if we already detected a root mismatch or if we didn't record the Sync Committee head (expected after a restart)

