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

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (s *Service) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.multinode").Start(ctx, "SubmitSyncCommitteeContributions", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if len(contributionAndProofs) == 0 {
		return errors.New("no sync committee contribution and proofs supplied")
	}

	var err error
	sem := semaphore.NewWeighted(s.processConcurrency)
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.syncCommitteeContributionsSubmitters {
		go s.submitSyncCommitteeContributions(ctx, sem, w, name, contributionAndProofs, submitter)
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

// submitSyncCommitteeContributions carries out the internal work of submitting sync committee contributions.
// skipcq: RVV-B0001
func (s *Service) submitSyncCommitteeContributions(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	name string,
	contributionAndProofs []*altair.SignedContributionAndProof,
	submitter eth2client.SyncCommitteeContributionsSubmitter,
) {
	log := log.With().Str("beacon_node_address", name).Uint64("slot", uint64(contributionAndProofs[0].Message.Contribution.Slot)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err := submitter.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
	if err != nil {
		err = s.handleSubmitSyncCommitteeContributionsError(ctx, submitter, err)
	}

	s.clientMonitor.ClientOperation(address, "submit sync committee contribution and proofs", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit sync committee contribution and proofs")
		return
	}

	w.Signal()
	log.Trace().Msg("Submitted sync committee contribution and proofs")
}

func (s *Service) handleSubmitSyncCommitteeContributionsError(ctx context.Context,
	submitter eth2client.SyncCommitteeContributionsSubmitter,
	err error,
) error {
	// Fetch the JSON response from the error.
	errorStr := err.Error()
	jsonIndex := strings.Index(errorStr, "{")
	if jsonIndex == -1 {
		return err
	}

	serverType, address := s.serviceInfo(ctx, submitter)
	allowedFailures := 0
	if serverType == "lighthouse" {
		resp := lhErrorResponse{}
		if err := json.Unmarshal([]byte(errorStr[jsonIndex:]), &resp); err != nil {
			return err
		}
		for i := range len(resp.Failures) {
			switch {
			case strings.HasPrefix(resp.Failures[i].Message, "Verification: AggregatorAlreadyKnown"):
				log.Trace().Str("beacon_node_address", address).Int("index", resp.Failures[i].Index).Msg("Contribution and proof already received for that slot; ignoring")
				allowedFailures++
			default:
				log.Trace().Str("beacon_node_address", address).Int("index", resp.Failures[i].Index).Str("msg", resp.Failures[i].Message).Msg("Real lighthouse error")
			}
		}
		if len(resp.Failures) == allowedFailures {
			log.Trace().Str("beacon_node_address", address).Msg("Errors from node are allowable; no error")
			return nil
		}
	}

	return err
}
