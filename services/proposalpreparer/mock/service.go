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

	"github.com/attestantio/vouch/services/proposalpreparer"
)

// Service is a mock proposal preparer.
type Service struct{}

// New creates a new mock proposal preparer.
func New() proposalpreparer.Service {
	return &Service{}
}

// UpdatePreparations updates the preparations for validators on the beacon nodes.
func (s *Service) UpdatePreparations(_ context.Context) error {
	return nil
}
