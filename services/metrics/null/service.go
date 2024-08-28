// Copyright © 2020 - 2024 Attestant Limited.
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

// Package null is a null metrics logger.
package null

// Service is a metrics service that drops metrics.
type Service struct{}

// New creates a new null metrics service.
func New() *Service {
	return &Service{}
}

// Presenter provides the presenter for this service.
func (*Service) Presenter() string {
	return "null"
}
