// Copyright © 2020 Attestant Limited.
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

package mock

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attestationaggregator"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// service is a mock.
type service struct{}

// New creates a mock attestation aggregator.
func New() attestationaggregator.Service {
	return &service{}
}

// Aggregate is a mock.
func (*service) Aggregate(_ context.Context, _ *attestationaggregator.Duty) {}

// AggregatorsAndSignatures reports signatures and whether validators are attestation aggregators for a given slot.
func (*service) AggregatorsAndSignatures(_ context.Context,
	_ []e2wtypes.Account,
	_ phase0.Slot,
	_ []uint64,
) ([]phase0.BLSSignature, []bool, error) {
	return nil, nil, nil
}
