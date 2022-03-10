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

package remote

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

type feeRecipientsResponseJSON struct {
	FeeRecipients []*feeRecipientResponseJSON `json:"fee_recipients"`
}

type feeRecipientResponseJSON struct {
	Index        uint64 `json:"index"`
	FeeRecipient string `json:"fee_recipient"`
}

type errorResponseJSON struct {
	Error string `json:"error"`
}

// FeeRecipients returns the fee recipients for the given validators.
func (s *Service) FeeRecipients(ctx context.Context,
	indices []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
	error,
) {
	started := time.Now()

	feeRecipients, err := s.feeRecipients(ctx, indices)
	if err != nil {
		feeRecipientsCompleted(started, "failed")
		return nil, err
	}

	feeRecipientsCompleted(started, "succeeded")
	return feeRecipients, nil
}

func (s *Service) feeRecipients(ctx context.Context,
	indices []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
	error,
) {
	res := make(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress, len(indices))

	data, err := s.fetchFeeRecipientsFromRemote(ctx, indices)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain fee recipients from remote")
	}
	if data != nil {
		for _, feeRecipientData := range data.FeeRecipients {
			bytes, err := hex.DecodeString(strings.TrimPrefix(feeRecipientData.FeeRecipient, "0x"))
			if err != nil {
				log.Error().Err(err).Uint64("index", feeRecipientData.Index).Str("fee_recipient", feeRecipientData.FeeRecipient).Msg("Failed to parse fee recipient address")
				// TODO metrics
				continue
			}
			feeRecipient := bellatrix.ExecutionAddress{}
			copy(feeRecipient[:], bytes)
			res[phase0.ValidatorIndex(feeRecipientData.Index)] = feeRecipient
			feeRecipientObtained("remote")
		}
	}

	if len(res) != len(indices) {
		s.padResults(ctx, indices, res)
	}

	s.cacheMu.Lock()
	s.cache = res
	s.cacheMu.Unlock()

	return res, nil
}

// fetchFeeRecipientsFromRemote fetches fee recipients from the remote source.
func (s *Service) fetchFeeRecipientsFromRemote(ctx context.Context,
	indices []phase0.ValidatorIndex,
) (
	*feeRecipientsResponseJSON,
	error,
) {
	// Create the request body.
	body := new(bytes.Buffer)
	_, err := body.WriteString(`{"indices":[`)
	if err != nil {
		return nil, errors.Wrap(err, "buffer write failed")
	}
	for i, index := range indices {
		if i != 0 {
			body.WriteString(",")
		}
		body.WriteString(fmt.Sprintf("%d", index))
	}
	body.WriteString(`]}`)

	url := fmt.Sprintf("%s/feerecipients", s.baseURL)
	log.Trace().Str("url", url).Msg("Calling fee recipients endpoint")

	resp, err := s.client.Post(url, "application/json", body)
	if err != nil {
		// Return server-supplied error if available.
		if resp != nil && resp.Body != nil {
			var errDetails errorResponseJSON
			if err := json.NewDecoder(resp.Body).Decode(&errDetails); err != nil {
				return nil, fmt.Errorf("failed to obtain fee recipients: %s", errDetails.Error)
			}
		}
		return nil, err
	}

	var data feeRecipientsResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "failed to parse fee recipients response")
	}

	return &data, nil
}

// padResults fills in the results that have not been obtained remotely, either
// from the cache or the default results.
func (s *Service) padResults(ctx context.Context,
	indices []phase0.ValidatorIndex,
	res map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
) {
	for _, index := range indices {
		if _, exists := res[index]; !exists {
			s.padResult(ctx, index, res)
		}
	}
}

// padResult fills in a result that has not been obtained remotely, either
// from the cache or the default results.
func (s *Service) padResult(ctx context.Context,
	index phase0.ValidatorIndex,
	res map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
) {
	s.cacheMu.RLock()
	feeRecipient, exists := s.cache[index]
	s.cacheMu.RUnlock()

	if exists {
		res[index] = feeRecipient
		feeRecipientObtained("cache")
	} else {
		res[index] = s.defaultFeeRecipient
		feeRecipientObtained("default")
	}
}
