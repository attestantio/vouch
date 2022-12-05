// Copyright © 2021, 2022 Attestant Limited.
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

package multinode

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitSyncCommitteeMessages submits sync committee messages.
func (s *Service) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.multinode").Start(ctx, "SubmitSyncCommitteeMessages", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if len(messages) == 0 {
		return errors.New("no sync committee messages supplied")
	}

	var err error
	sem := semaphore.NewWeighted(s.processConcurrency)
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.syncCommitteeMessagesSubmitter {
		go s.submitSyncCommitteeMessages(ctx, sem, w, name, messages, submitter)
	}
	// Also set a timeout condition, in case no submitters return.
	go func(s *Service, w *sync.Cond) {
		time.Sleep(s.timeout)
		err = errors.New("no successful submissions before timeout")
		w.Signal()
	}(s, w)
	w.Wait()
	w.L.Unlock()

	return err
}

// submitSyncCommitteeMessages carries out the internal work of submitting sync committee messages.
// skipcq: RVV-B0001
func (s *Service) submitSyncCommitteeMessages(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	name string,
	messages []*altair.SyncCommitteeMessage,
	submitter eth2client.SyncCommitteeMessagesSubmitter,
) {
	log := log.With().Str("beacon_node_address", name).Uint64("slot", uint64(messages[0].Slot)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err := submitter.SubmitSyncCommitteeMessages(ctx, messages)
	if err != nil {
		err = s.handleSubmitSyncCommitteeMessagesError(ctx, submitter, err)
	}

	s.clientMonitor.ClientOperation(address, "submit sync committee messages", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit sync committee messages")
		return
	}

	w.Signal()
	log.Trace().Msg("Submitted sync committee messages")
}

type lhErrorResponse struct {
	Code     int                       `json:"code"`
	Message  string                    `json:"string"`
	Failures []*lhErrorResponseFailure `json:"failures"`
}

type lhErrorResponseFailure struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

type tekuErrorResponse struct {
	Code     string                      `json:"code"`
	Message  string                      `json:"string"`
	Failures []*tekuErrorResponseFailure `json:"failures"`
}

type tekuErrorResponseFailure struct {
	Index   string `json:"index"`
	Message string `json:"message"`
}

func (s *Service) handleSubmitSyncCommitteeMessagesError(ctx context.Context,
	submitter eth2client.SyncCommitteeMessagesSubmitter,
	err error,
) error {
	// Fetch the JSON response from the error.
	errorStr := err.Error()
	jsonIndex := strings.Index(errorStr, "{")
	if jsonIndex == -1 {
		log.Warn().Err(err).Msg("Failed to submit sync committee messages")
		return err
	}

	serverType, provider := s.serviceInfo(ctx, submitter)
	allowedFailures := 0
	switch serverType {
	case "lighthouse":
		resp := lhErrorResponse{}
		if jsonErr := json.Unmarshal([]byte(errorStr[jsonIndex:]), &resp); jsonErr != nil {
			log.Warn().Err(err).Msg("Failed to submit sync committee messages")
			return err
		}
		for i := 0; i < len(resp.Failures); i++ {
			switch {
			case strings.HasPrefix(resp.Failures[i].Message, "Verification: PriorSyncCommitteeMessageKnown"):
				log.Trace().Str("provider", provider).Int("index", resp.Failures[i].Index).Msg("Message already received for that slot; ignoring")
				allowedFailures++
			default:
				log.Trace().Str("provider", provider).Int("index", resp.Failures[i].Index).Str("msg", resp.Failures[i].Message).Msg("Real lighthouse error")
			}
		}
		if len(resp.Failures) == allowedFailures {
			log.Trace().Str("provider", provider).Msg("Errors from node are allowable; continuing")
			return nil
		}
	case "teku":
		resp := tekuErrorResponse{}
		if jsonErr := json.Unmarshal([]byte(errorStr[jsonIndex:]), &resp); jsonErr != nil {
			log.Trace().Err(err).Msg("Failed to submit sync committee messages")
			return err
		}
		for i := 0; i < len(resp.Failures); i++ {
			switch {
			case resp.Failures[i].Message == "Ignoring sync committee message as a duplicate was processed during validation":
				log.Trace().Str("provider", provider).Str("index", resp.Failures[i].Index).Msg("Message already received for that slot; ignoring")
				allowedFailures++
			default:
				log.Trace().Str("provider", provider).Str("index", resp.Failures[i].Index).Str("msg", resp.Failures[i].Message).Msg("Real teku error")
			}
		}
		if len(resp.Failures) == allowedFailures {
			log.Trace().Str("provider", provider).Msg("Errors from Lighthouse node are allowable; continuing")
			return nil
		}
	}

	log.Warn().Str("server", serverType).Err(err).Msg("Failed to submit sync committee messages")
	return err
}
