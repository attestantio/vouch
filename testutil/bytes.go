// Copyright © 2020 Attestant Limited.
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

package testutil

import (
	"encoding/hex"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// HexToBytes converts a hex string to a byte array.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToBytes(input string) []byte {
	res, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	return res
}

// HexToBytes32 converts a hex string to a 32-byte array.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToBytes32(input string) [32]byte {
	tmp, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	res := [32]byte{}
	copy(res[:], tmp)

	return res
}

// HexToPubKey converts a hex string to a spec public key.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToPubKey(input string) phase0.BLSPubKey {
	data := HexToBytes(input)
	var res phase0.BLSPubKey
	copy(res[:], data)
	return res
}

// HexToSignature converts a hex string to a spec signature.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToSignature(input string) phase0.BLSSignature {
	data := HexToBytes(input)
	var res phase0.BLSSignature
	copy(res[:], data)
	return res
}

// HexToDomainType converts a hex string to a spec domain type.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToDomainType(input string) phase0.DomainType {
	data := HexToBytes(input)
	var res phase0.DomainType
	copy(res[:], data)
	return res
}

// HexToDomain converts a hex string to a spec domain.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToDomain(input string) phase0.Domain {
	data := HexToBytes(input)
	var res phase0.Domain
	copy(res[:], data)
	return res
}

// HexToVersion converts a hex string to a spec version.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToVersion(input string) phase0.Version {
	data := HexToBytes(input)
	var res phase0.Version
	copy(res[:], data)
	return res
}

// HexToRoot converts a hex string to a spec root.
// This should only be used for pre-defined test strings; it will panic if the input is invalid.
func HexToRoot(input string) phase0.Root {
	data := HexToBytes(input)
	var res phase0.Root
	copy(res[:], data)
	return res
}
