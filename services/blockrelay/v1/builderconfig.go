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

package v1

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

// BuilderConfig is the builder configuration for a specific proposer.
type BuilderConfig struct {
	Enabled bool
	Grace   time.Duration
	Relays  []string
}

type builderConfigJSON struct {
	Enabled bool     `json:"enabled"`
	Grace   string   `json:"grace,omitempty"`
	Relays  []string `json:"relays,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (b *BuilderConfig) MarshalJSON() ([]byte, error) {
	var grace string
	if b.Grace > 0 {
		grace = fmt.Sprintf("%d", b.Grace.Milliseconds())
	}
	return json.Marshal(&builderConfigJSON{
		Enabled: b.Enabled,
		Grace:   grace,
		Relays:  b.Relays,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BuilderConfig) UnmarshalJSON(input []byte) error {
	var data builderConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	b.Enabled = data.Enabled

	if data.Grace != "" {
		grace, err := strconv.ParseInt(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
		}
		if grace < 0 {
			return errors.New("grace cannot be negative")
		}
		b.Grace = time.Duration(grace) * time.Millisecond
	}

	if b.Enabled && len(data.Relays) == 0 {
		return errors.New("relays missing")
	}
	b.Relays = data.Relays

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
