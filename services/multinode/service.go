// Copyright © 2023 Attestant Limited.
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

// package multinode handles multiple active Vouch instances.
package multinode

import (
	"context"
)

// Service provides a multinode service.
type Service interface{}

// ActivityProvider provides information on the activity state of a node.
type ActivityProvider interface {
	// ShouldValidate returns true if this node should carry out validating operations.
	ShouldValidate(ctx context.Context) bool
}
