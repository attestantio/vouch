// Copyright © 2024 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package multiinstance manages co-ordination of multiple instance validator actions.
package multiinstance

import (
	"context"

	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
)

// Service is the multi instance service.
type Service interface {
	// ShouldAttest returns true if this Vouch instance should attest.
	ShouldAttest(ctx context.Context, duty *attester.Duty) bool

	// OnAttestationFailure flags that an attempt to attest has failed.
	OnAttestationFailure(ctx context.Context, duty *attester.Duty)

	// ShouldPropose returns true if this Vouch instance should propose.
	ShouldPropose(ctx context.Context, duty *beaconblockproposer.Duty) bool

	// OnProposalFailure flags that an attempt to propose has failed.
	OnProposalFailure(ctx context.Context, duty *beaconblockproposer.Duty)
}
