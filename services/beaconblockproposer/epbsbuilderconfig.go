// Copyright © 2026 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// EPBSBuilderConfig is a resolved ePBS policy for a proposer.
type EPBSBuilderConfig struct {
	MinBid             phase0.Gwei
	BuilderBoostFactor uint64
	Builders           []*EPBSBuilder
}

// EPBSBuilder is a resolved direct-builder policy.
type EPBSBuilder struct {
	URL                 string
	AuthData            []byte
	BuilderPubkeys      []phase0.BLSPubKey
	MaxExecutionPayment phase0.Gwei
	MinBid              phase0.Gwei
	BuilderBoostFactor  uint64
}

type epbsBuilderConfigJSON struct {
	MinBid             string         `json:"min_bid"`
	BuilderBoostFactor uint64         `json:"builder_boost_factor"`
	Builders           []*EPBSBuilder `json:"builders"`
}

type epbsBuilderJSON struct {
	URL                 string   `json:"url"`
	AuthData            string   `json:"auth_data"`
	BuilderPubkeys      []string `json:"builder_pubkeys"`
	MaxExecutionPayment string   `json:"max_execution_payment"`
	MinBid              string   `json:"min_bid"`
	BuilderBoostFactor  uint64   `json:"builder_boost_factor"`
}

// MarshalJSON implements json.Marshaler.
func (c *EPBSBuilderConfig) MarshalJSON() ([]byte, error) {
	builders := c.Builders
	if builders == nil {
		builders = []*EPBSBuilder{}
	}

	return json.Marshal(&epbsBuilderConfigJSON{
		MinBid:             fmt.Sprintf("%d", c.MinBid),
		BuilderBoostFactor: c.BuilderBoostFactor,
		Builders:           builders,
	})
}

// MarshalJSON implements json.Marshaler without exposing authorization data.
func (b *EPBSBuilder) MarshalJSON() ([]byte, error) {
	pubkeys := make([]string, len(b.BuilderPubkeys))
	for i := range b.BuilderPubkeys {
		pubkeys[i] = fmt.Sprintf("%#x", b.BuilderPubkeys[i])
	}

	return json.Marshal(&epbsBuilderJSON{
		URL:                 b.URL,
		AuthData:            "redacted",
		BuilderPubkeys:      pubkeys,
		MaxExecutionPayment: fmt.Sprintf("%d", b.MaxExecutionPayment),
		MinBid:              fmt.Sprintf("%d", b.MinBid),
		BuilderBoostFactor:  b.BuilderBoostFactor,
	})
}
