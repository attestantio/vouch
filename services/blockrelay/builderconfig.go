// Copyright © 2022 Attestant Limited.
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

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
)

// BuilderConfig is the builder configuration for a specific proposer.
type BuilderConfig struct {
	Enabled  bool
	Relays   []string
	GasLimit uint64
}

type builderConfigJSON struct {
	Enabled  bool     `json:"enabled"`
	Relays   []string `json:"relays,omitempty"`
	GasLimit string   `json:"gas_limit"`
}

// MarshalJSON implements json.Marshaler.
func (b *BuilderConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&builderConfigJSON{
		Enabled:  b.Enabled,
		Relays:   b.Relays,
		GasLimit: fmt.Sprintf("%d", b.GasLimit),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BuilderConfig) UnmarshalJSON(input []byte) error {
	var data builderConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	b.Enabled = data.Enabled
	b.Relays = data.Relays
	var err error
	b.GasLimit, err = strconv.ParseUint(data.GasLimit, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid gas limit")
	}

	return nil
}

// String provides a string representation of the struct.
func (b *BuilderConfig) String() string {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
