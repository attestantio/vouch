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

import (
	"fmt"
	"strings"
)

// ConfigVersion defines the spec version of the configuration in a response.
type ConfigVersion int

const (
	// ConfigVersionV1 is data applicable for the first version of the configuration.
	ConfigVersionV1 ConfigVersion = iota
	// ConfigVersionV2 is data applicable for the second version of the configuration.
	ConfigVersionV2
)

var configVersionStrings = [...]string{
	"v1",
	"v2",
}

// MarshalJSON implements json.Marshaler.
func (c *ConfigVersion) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", configVersionStrings[*c])), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *ConfigVersion) UnmarshalJSON(input []byte) error {
	var err error
	switch strings.ToLower(string(input)) {
	case `"v1"`:
		*c = ConfigVersionV1
	case `"v2"`:
		*c = ConfigVersionV2
	default:
		err = fmt.Errorf("unrecognised config version %s", string(input))
	}
	return err
}

// String returns a string representation of the version.
func (c *ConfigVersion) String() string {
	if int(*c) >= len(configVersionStrings) {
		return "unknown"
	}
	return configVersionStrings[*c]
}
