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

// Package beaconcommitteesubscriber is a package that manages subscriptions for beacon committees.
package beaconcommitteesubscriber

import (
	"context"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Subscription holds details of the committees to which we are subscribing.
type Subscription struct {
	Duty         *api.AttesterDuty
	IsAggregator bool
	Signature    phase0.BLSSignature
}

// Service is the beacon committee subscriber service.
type Service interface {
	// Subscribe subscribes to beacon committees for a given epoch.
	Subscribe(ctx context.Context,
		epoch phase0.Epoch,
		accounts map[phase0.ValidatorIndex]e2wtypes.Account,
	) (map[phase0.Slot]map[phase0.CommitteeIndex]*Subscription, error)
}
