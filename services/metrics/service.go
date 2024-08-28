// Copyright © 2020, 2021 Attestant Limited.
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

// Package metrics tracks various metrics that measure the performance of vouch.
package metrics

// Service is the generic metrics service.
type Service interface {
	// Presenter provides the presenter for this service.
	Presenter() string
}

// ValidatorsManagerMonitor provides methods to monitor the validators manager.
type ValidatorsManagerMonitor interface{}

// SignerMonitor provides methods to monitor signers.
type SignerMonitor interface{}
