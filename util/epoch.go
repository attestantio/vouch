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

package util

import "github.com/attestantio/go-eth2-client/spec/phase0"

// EpochToInt64 converts an epoch to an int64.
func EpochToInt64(epoch phase0.Epoch) int64 {
	if epoch > 0x7fffffffffffffff {
		panic("epoch too large to convert to int64")
	}

	//nolint:gosec
	return int64(epoch)
}
