// Copyright © 2025 Attestant Limited.
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

package combined

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type attestationPoolResponse struct {
	provider     string
	attestations []*spec.VersionedAttestation
}

type attestationPoolError struct {
	provider string
	err      error
}

// AttestationPool provides the combined attestation pools from a number of beacon nodes.
func (s *Service) AttestationPool(ctx context.Context,
	opts *api.AttestationPoolOpts,
) (
	*api.Response[[]*spec.VersionedAttestation],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationpool.combined").Start(ctx, "AttestationPool")
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().Logger()
	if opts.Slot != nil {
		log = log.With().Uint64("slot", uint64(*opts.Slot)).Logger()
	}

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.attestationPoolProviders)

	respCh := make(chan *attestationPoolResponse, requests)
	errCh := make(chan *attestationPoolError, requests)
	// Kick off the requests.
	for name, provider := range s.attestationPoolProviders {
		go s.attestationPool(ctx, started, name, provider, respCh, errCh, opts)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0

	attestations := make(map[phase0.Root]*spec.VersionedAttestation)

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Response received")
			for _, attestation := range resp.attestations {
				root, err := attestation.HashTreeRoot()
				if err != nil {
					log.Warn().Err(err).Msg("Failed to obtain hash tree root for attestation")
					continue
				}
				attestations[root] = attestation
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Err(err.err).
				Msg("Error received")
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = requests - responded - errored
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("responded", responded).
					Int("errored", errored).
					Int("timed_out", timedOut).
					Msg("Soft timeout reached with responses")
			} else {
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("errored", errored).
					Msg("Soft timeout reached with no responses")
			}
			// Set the number of requests that have soft timed out.
			softTimedOut = requests - responded - errored - timedOut
		}
	}
	softCancel()

	// Loop 2: after soft timeout.
	for responded+errored+timedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Response received")
			for _, attestation := range resp.attestations {
				root, err := attestation.HashTreeRoot()
				if err != nil {
					log.Warn().Err(err).Msg("Failed to obtain hash tree root for attestation")
					continue
				}
				attestations[root] = attestation
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			timedOut = requests - responded - errored
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Hard timeout reached")
		}
	}
	cancel()
	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", responded).
		Int("errored", errored).
		Int("timed_out", timedOut).
		Msg("Results")

	attestationsSlice := make([]*spec.VersionedAttestation, 0, len(attestations))
	for _, attestation := range attestations {
		attestationsSlice = append(attestationsSlice, attestation)
	}

	return &api.Response[[]*spec.VersionedAttestation]{
		Data:     attestationsSlice,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) attestationPool(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.AttestationPoolProvider,
	respCh chan *attestationPoolResponse,
	errCh chan *attestationPoolError,
	opts *api.AttestationPoolOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationpool.combined").Start(ctx, "attestationPool", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	response, err := provider.AttestationPool(ctx, opts)
	s.clientMonitor.ClientOperation(name, "attestation pool", err == nil, time.Since(started))
	if err != nil {
		errCh <- &attestationPoolError{
			provider: name,
			err:      err,
		}
		return
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation pool")

	respCh <- &attestationPoolResponse{
		provider:     name,
		attestations: response.Data,
	}
}
