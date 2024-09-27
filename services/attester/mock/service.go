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

package mock

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attester"
)

// Service is a mock attester.
type Service struct{}

// New creates a new mock  attester.
func New() *Service {
	return &Service{}
}

// Attest carries out attestations for a slot.
func (*Service) Attest(_ context.Context, _ *attester.Duty) ([]*phase0.Attestation, error) {
	return make([]*phase0.Attestation, 0), nil
}
