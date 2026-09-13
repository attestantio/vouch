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

package v2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

const (
	maxEPBSBuilders        = 64
	maxEPBSBuilderURLBytes = 2048
	maxEPBSAuthDataBytes   = 4096
	maxEPBSBuilderPubkeys  = 64
)

// EPBSBuilderConfig contains the optional ePBS policy at one configuration level.
type EPBSBuilderConfig struct {
	MinBid             *phase0.Gwei
	BuilderBoostFactor *uint64
	Builders           *[]*EPBSBuilder
}

// EPBSBuilder contains the configuration for one direct builder.
type EPBSBuilder struct {
	URL                 string
	AuthData            []byte
	BuilderPubkeys      []phase0.BLSPubKey
	MaxExecutionPayment phase0.Gwei
	MinBid              phase0.Gwei
	BuilderBoostFactor  uint64
}

type epbsBuilderConfigJSON struct {
	MinBid             string          `json:"min_bid,omitempty"`
	BuilderBoostFactor *uint64         `json:"builder_boost_factor,omitempty"`
	Builders           *[]*EPBSBuilder `json:"builders,omitempty"`
}

type epbsBuilderJSON struct {
	URL                 string    `json:"url"`
	AuthData            string    `json:"auth_data"`
	BuilderPubkeys      *[]string `json:"builder_pubkeys"`
	MaxExecutionPayment string    `json:"max_execution_payment"`
	MinBid              string    `json:"min_bid"`
	BuilderBoostFactor  *uint64   `json:"builder_boost_factor"`
}

// MarshalJSON implements json.Marshaler.
func (c *EPBSBuilderConfig) MarshalJSON() ([]byte, error) {
	var minBid string
	if c.MinBid != nil {
		minBid = fmt.Sprintf("%d", *c.MinBid)
	}

	return json.Marshal(&epbsBuilderConfigJSON{
		MinBid:             minBid,
		BuilderBoostFactor: c.BuilderBoostFactor,
		Builders:           c.Builders,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *EPBSBuilderConfig) UnmarshalJSON(input []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return errors.Wrap(err, "invalid ePBS builder config")
	}
	if builders, exists := fields["builders"]; exists && bytes.Equal(bytes.TrimSpace(builders), []byte("null")) {
		return errors.New("ePBS direct builders must be an array")
	}
	if minBid, exists := fields["min_bid"]; exists && bytes.Equal(bytes.TrimSpace(minBid), []byte("null")) {
		return errors.New("ePBS minimum bid must be a decimal string")
	}
	if boost, exists := fields["builder_boost_factor"]; exists && bytes.Equal(bytes.TrimSpace(boost), []byte("null")) {
		return errors.New("ePBS builder boost factor must be an unsigned integer")
	}

	var data epbsBuilderConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid ePBS builder config")
	}
	if data.MinBid != "" {
		minBid, err := strconv.ParseUint(data.MinBid, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid ePBS minimum bid")
		}
		value := phase0.Gwei(minBid)
		c.MinBid = &value
	}
	if data.Builders != nil {
		if len(*data.Builders) > maxEPBSBuilders {
			return errors.New("ePBS builder config has more than 64 direct builders")
		}
		seen := make(map[string]struct{}, len(*data.Builders))
		for i, builder := range *data.Builders {
			if builder == nil {
				return fmt.Errorf("direct builder %d is null", i)
			}
			key := builder.URL + "\x00" + string(builder.AuthData)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("direct builder %d duplicates an earlier URL and authorization", i)
			}
			seen[key] = struct{}{}
		}
	}
	c.BuilderBoostFactor = data.BuilderBoostFactor
	c.Builders = data.Builders

	return nil
}

// MarshalJSON implements json.Marshaler without exposing authorization data.
func (b *EPBSBuilder) MarshalJSON() ([]byte, error) {
	pubkeys := make([]string, len(b.BuilderPubkeys))
	for i := range b.BuilderPubkeys {
		pubkeys[i] = fmt.Sprintf("%#x", b.BuilderPubkeys[i])
	}
	boost := b.BuilderBoostFactor

	return json.Marshal(&epbsBuilderJSON{
		URL:                 b.URL,
		AuthData:            "redacted",
		BuilderPubkeys:      &pubkeys,
		MaxExecutionPayment: fmt.Sprintf("%d", b.MaxExecutionPayment),
		MinBid:              fmt.Sprintf("%d", b.MinBid),
		BuilderBoostFactor:  &boost,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *EPBSBuilder) UnmarshalJSON(input []byte) error {
	var data epbsBuilderJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid direct builder")
	}

	if err := validateEPBSBuilderURL(data.URL); err != nil {
		return err
	}
	authData, err := parseEPBSAuthData(data.AuthData)
	if err != nil {
		return err
	}
	pubkeys, err := parseEPBSBuilderPubkeys(data.BuilderPubkeys)
	if err != nil {
		return err
	}
	maxExecutionPayment, err := parseRequiredGwei(data.MaxExecutionPayment, "direct builder max execution payment")
	if err != nil {
		return err
	}
	minBid, err := parseRequiredGwei(data.MinBid, "direct builder minimum bid")
	if err != nil {
		return err
	}
	if data.BuilderBoostFactor == nil {
		return errors.New("direct builder boost factor is missing")
	}

	b.URL = data.URL
	b.AuthData = authData
	b.BuilderPubkeys = pubkeys
	b.MaxExecutionPayment = maxExecutionPayment
	b.MinBid = minBid
	b.BuilderBoostFactor = *data.BuilderBoostFactor

	return nil
}

func validateEPBSBuilderURL(input string) error {
	if input == "" {
		return errors.New("direct builder URL is missing")
	}
	if len([]byte(input)) > maxEPBSBuilderURLBytes {
		return errors.New("direct builder URL exceeds 2048 bytes")
	}
	parsed, err := url.ParseRequestURI(input)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("direct builder URL is invalid")
	}

	return nil
}

func parseEPBSAuthData(input string) ([]byte, error) {
	if input == "" {
		return nil, errors.New("direct builder authorization data is missing")
	}
	if !strings.HasPrefix(input, "0x") {
		return nil, errors.New("direct builder authorization data is missing 0x prefix")
	}
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		return nil, errors.New("direct builder authorization data is invalid hex")
	}
	if len(data) == 0 {
		return nil, errors.New("direct builder authorization data is empty")
	}
	if len(data) > maxEPBSAuthDataBytes {
		return nil, errors.New("direct builder authorization data exceeds 4096 bytes")
	}

	return data, nil
}

func parseEPBSBuilderPubkeys(input *[]string) ([]phase0.BLSPubKey, error) {
	if input == nil {
		return nil, errors.New("direct builder public key allowlist is missing")
	}
	if len(*input) > maxEPBSBuilderPubkeys {
		return nil, errors.New("direct builder public key allowlist has more than 64 entries")
	}

	res := make([]phase0.BLSPubKey, len(*input))
	for i, inputPubkey := range *input {
		if !strings.HasPrefix(inputPubkey, "0x") {
			return nil, fmt.Errorf("direct builder public key %d is missing 0x prefix", i)
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(inputPubkey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("direct builder public key %d is invalid hex", i)
		}
		if len(decoded) != phase0.PublicKeyLength {
			return nil, fmt.Errorf("direct builder public key %d has incorrect length", i)
		}
		copy(res[i][:], decoded)
	}

	return res, nil
}

func parseRequiredGwei(input string, field string) (phase0.Gwei, error) {
	if input == "" {
		return 0, fmt.Errorf("%s is missing", field)
	}
	value, err := strconv.ParseUint(input, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid", field)
	}

	return phase0.Gwei(value), nil
}
