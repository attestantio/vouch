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

	"github.com/attestantio/vouch/services/beaconblockproposer"
)

type service struct{}

// New is a mock.
func New() beaconblockproposer.Service {
	return &service{}
}

// Prepare is a mock.
func (*service) Prepare(_ context.Context, _ interface{}) error {
	return nil
}

// Propose is a mock.
func (*service) Propose(_ context.Context, _ interface{}) {}
