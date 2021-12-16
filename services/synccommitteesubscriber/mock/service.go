// Copyright © 2021 Attestant Limited.
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

	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/synccommitteesubscriber"
)

type service struct{}

// New is a mock sync committee subscriber service.
func New() synccommitteesubscriber.Service {
	return &service{}
}

// Subscribe is a mock.
func (*service) Subscribe(_ context.Context,
	_ spec.Epoch,
	_ []*api.SyncCommitteeDuty,
) error {
	return nil
}
