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

package blockrelay

import "math/big"

// StandardBuilderCategory is the default category for builders.
const StandardBuilderCategory = "standard"

// BuilderConfig is the configuration for builders.
type BuilderConfig struct {
	// Category is the category applied to the builder.
	Category string
	// Boost is a percentage multiplier applied to the proposal score from the builder.
	Boost *big.Int
	// Offset is an offset applied to the proposal score from the builder.
	Offset *big.Int
}
