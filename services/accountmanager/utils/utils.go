package utils

import apiv1 "github.com/attestantio/go-eth2-client/api/v1"

// IsSyncCommitteeEligible returns true if the validator is in a state that is eligible for Sync Committee duty.
func IsSyncCommitteeEligible(state apiv1.ValidatorState) bool {
	return state == apiv1.ValidatorStateActiveOngoing || state == apiv1.ValidatorStateActiveExiting ||
		state == apiv1.ValidatorStateExitedUnslashed || state == apiv1.ValidatorStateActiveSlashed ||
		state == apiv1.ValidatorStateExitedSlashed || state == apiv1.ValidatorStateWithdrawalPossible
}
