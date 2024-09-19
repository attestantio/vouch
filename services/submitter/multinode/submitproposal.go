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

package multinode

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitProposal submits a proposal.
func (s *Service) SubmitProposal(ctx context.Context, proposal *api.VersionedSignedProposal) error {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "SubmitProposal", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if proposal == nil {
		return errors.New("no proposal supplied")
	}

	var err error
	sem := semaphore.NewWeighted(s.processConcurrency)
	submissionCompleted := &atomic.Bool{}
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.proposalSubmitters {
		go s.submitProposal(ctx, sem, w, submissionCompleted, name, proposal, submitter)
	}
	// Also set a timeout condition, in case no submitters return.
	go func(s *Service, w *sync.Cond) {
		time.Sleep(s.timeout)
		w.Signal()
	}(s, w)
	w.Wait()
	w.L.Unlock()

	if !submissionCompleted.Load() {
		err = errors.New("no successful submissions before timeout")
	}

	return err
}

// submitProposal carries out the internal work of submitting beacon blocks.
// skipcq: RVV-B0001
func (s *Service) submitProposal(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	submissionCompleted *atomic.Bool,
	name string,
	proposal *api.VersionedSignedProposal,
	submitter eth2client.ProposalSubmitter,
) {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "submitProposal", trace.WithAttributes(
		attribute.String("server", name),
	))
	defer span.End()

	slot, err := proposal.Slot()
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain slot")
		return
	}
	log := s.log.With().Str("beacon_node_address", name).Uint64("slot", uint64(slot)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()

	err = submitter.SubmitProposal(ctx, &api.SubmitProposalOpts{
		Proposal: proposal,
	})
	s.clientMonitor.ClientOperation(address, "submit proposal", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit proposal")
		return
	}

	submissionCompleted.Store(true)
	w.Signal()
	log.Trace().Msg("Submitted proposal")
}
