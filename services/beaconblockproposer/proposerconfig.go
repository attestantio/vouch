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

package beaconblockproposer

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
)

// ProposerConfig contains configuration for a proposer.
type ProposerConfig struct {
	FeeRecipient bellatrix.ExecutionAddress
	Relays       []*RelayConfig
}

type proposerConfigJSON struct {
	FeeRecipient string         `json:"fee_recipient"`
	Relays       []*RelayConfig `json:"relays"`
}

// MarshalJSON implements json.Marshaler.
func (p *ProposerConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&proposerConfigJSON{
		FeeRecipient: fmt.Sprintf("%x", p.FeeRecipient),
		Relays:       p.Relays,
	})
}

// String provides a string representation of the struct.
func (p *ProposerConfig) String() string {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
