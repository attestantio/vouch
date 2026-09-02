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

package standard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// prewarmTimeout bounds an individual pre-warm request.  The response is discarded either
// way, so this exists only to stop a request outliving the slot to which it belongs.
const prewarmTimeout = 2 * time.Second

// prewarm asks each configured beacon node to produce a block for the proposal slot,
// discarding the result.
//
// Beacon nodes can carry per-slot work that only block production triggers, for example
// aggregating the attestation pool.  A node that has not produced a block for some time
// pays that cost on its next request, which places it on the critical path of a real
// proposal.  Issuing a throwaway request at the start of the slot moves the cost off that
// path: it runs concurrently with the auction, and the request whose result is used finds
// the work already carried out.
//
// The non-blinded endpoint is used deliberately, so that pre-warming cannot trigger a
// builder auction.
func (s *Service) prewarm(ctx context.Context, duty *beaconblockproposer.Duty) {
	if len(s.prewarmAddresses) == 0 {
		return
	}

	// The pre-warm is unrelated to the outcome of the proposal, so it neither inherits
	// cancellation from it nor outlives its own deadline.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), prewarmTimeout)
	defer cancel()

	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "Prewarm", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(duty.Slot())),
	))
	defer span.End()

	var wg sync.WaitGroup
	for _, address := range s.prewarmAddresses {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			s.prewarmNode(ctx, address, duty)
		}(address)
	}
	wg.Wait()
}

// prewarmNode pre-warms a single beacon node.  Failures are logged and otherwise ignored;
// a pre-warm that does not happen costs latency, not correctness.
func (s *Service) prewarmNode(ctx context.Context, address string, duty *beaconblockproposer.Duty) {
	started := time.Now()
	result := "failed"

	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "prewarmNode", trace.WithAttributes(
		attribute.String("provider", address),
	))
	defer func() {
		span.SetAttributes(attribute.String("result", result))
		span.End()
		monitorPrewarmed(address, started, result)
	}()

	log := s.log.With().Uint64("proposing_slot", uint64(duty.Slot())).Str("address", address).Logger()

	url := fmt.Sprintf("%s/eth/v2/validator/blocks/%d?randao_reveal=%s",
		prewarmBaseURL(address),
		uint64(duty.Slot()),
		duty.RANDAOReveal().String(),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create pre-warm request")

		return
	}
	req.Header.Set("Accept", "application/json")

	res, err := s.prewarmClient.Do(req)
	if err != nil {
		log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Pre-warm request failed")

		return
	}
	defer res.Body.Close()
	// The block is not wanted, only the work the node carried out to build it.  The body is
	// drained so that the connection can be re-used.
	_, _ = io.Copy(io.Discard, res.Body)

	span.SetAttributes(attribute.Int("status_code", res.StatusCode))
	if res.StatusCode == http.StatusOK {
		result = "succeeded"
	}

	log.Trace().
		Int("status_code", res.StatusCode).
		Dur("elapsed", time.Since(started)).
		Msg("Pre-warmed beacon node")
}

// prewarmBaseURL turns a beacon node address from the configuration into a usable URL.
func prewarmBaseURL(address string) string {
	if strings.Contains(address, "://") {
		return strings.TrimSuffix(address, "/")
	}

	return "http://" + strings.TrimSuffix(address, "/")
}
