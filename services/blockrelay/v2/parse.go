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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
)

// isNullField reports whether the named field is present and set to null.
func isNullField(fields map[string]json.RawMessage, name string) bool {
	value, exists := fields[name]

	return exists && bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

// firstSet returns the first non-nil value, or the fallback if all are nil.
func firstSet[T any](fallback T, values ...*T) T {
	for _, value := range values {
		if value != nil {
			return *value
		}
	}

	return fallback
}

// parseProposer parses a proposer as either a public key or an account regular expression.
func parseProposer(input string) (phase0.BLSPubKey, *regexp.Regexp, error) {
	var validator phase0.BLSPubKey
	if input == "" {
		return validator, nil, errors.New("proposer is missing")
	}
	if strings.HasPrefix(input, "0x") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
		if err != nil {
			return validator, nil, errors.Wrap(err, fmt.Sprintf("failed to decode proposer %s", input))
		}
		if len(tmp) != phase0.PublicKeyLength {
			return validator, nil, fmt.Errorf("incorrect length for proposer %s", input)
		}
		copy(validator[:], tmp)

		return validator, nil, nil
	}

	proposer := input
	if !strings.HasPrefix(proposer, "^") {
		proposer = fmt.Sprintf("^%s", proposer)
	}
	if !strings.HasSuffix(proposer, "$") {
		proposer = fmt.Sprintf("%s$", proposer)
	}
	account, err := regexp.Compile(proposer)
	if err != nil {
		return validator, nil, errors.Wrap(err, fmt.Sprintf("invalid account proposer %s", input))
	}

	return validator, account, nil
}

// parseFeeRecipient parses an optional fee recipient.
func parseFeeRecipient(input string) (*bellatrix.ExecutionAddress, error) {
	if input == "" {
		return nil, nil
	}
	tmp, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode fee recipient")
	}
	if len(tmp) != bellatrix.ExecutionAddressLength {
		return nil, errors.New("incorrect length for fee recipient")
	}
	var feeRecipient bellatrix.ExecutionAddress
	copy(feeRecipient[:], tmp)

	return &feeRecipient, nil
}

// parseGasLimit parses an optional gas limit.
func parseGasLimit(input string) (*uint64, error) {
	if input == "" {
		return nil, nil
	}
	gasLimit, err := strconv.ParseUint(input, 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "invalid gas limit")
	}

	return &gasLimit, nil
}

// parseGrace parses an optional grace period in milliseconds.
func parseGrace(input string) (*time.Duration, error) {
	if input == "" {
		return nil, nil
	}
	tmp, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "grace invalid")
	}
	if tmp < 0 {
		return nil, errors.New("grace cannot be negative")
	}
	grace := time.Duration(tmp) * time.Millisecond

	return &grace, nil
}

// parseMinValue parses an optional minimum value in ETH and returns it in wei.
func parseMinValue(input string) (*decimal.Decimal, error) {
	if input == "" {
		return nil, nil
	}
	minValue, err := decimal.NewFromString(input)
	if err != nil {
		return nil, errors.Wrap(err, "min value invalid")
	}
	if minValue.Sign() == -1 {
		return nil, errors.New("min value cannot be negative")
	}
	minValue = minValue.Mul(weiPerETH)

	return &minValue, nil
}
