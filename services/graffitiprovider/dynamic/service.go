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

package dynamic

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
	"go.opentelemetry.io/otel"
)

// Service is a graffiti provider service.
type Service struct {
	log              zerolog.Logger
	location         string
	fallbackLocation string
	majordomo        majordomo.Service
}

// New creates a new graffiti provider service.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "graffitiprovider").Str("impl", "dynamic").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:              log,
		location:         parameters.location,
		majordomo:        parameters.majordomo,
		fallbackLocation: parameters.fallbackLocation,
	}

	return s, nil
}

// Graffiti provides graffiti.
func (s *Service) Graffiti(ctx context.Context, slot phase0.Slot, validatorIndex phase0.ValidatorIndex) ([]byte, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.graffitiprovider.dyamic").Start(ctx, "Graffiti")
	defer span.End()

	// Replace location parameters with values.
	location := strings.ReplaceAll(s.location, "{{SLOT}}", fmt.Sprintf("%d", slot))
	location = strings.ReplaceAll(location, "{{VALIDATORINDEX}}", fmt.Sprintf("%d", validatorIndex))
	s.log.Trace().Str("location", location).Msg("Resolved graffiti location")

	// Fetch data from location, using fallback if required.
	data, err := s.majordomo.Fetch(ctx, location)
	if err != nil && s.fallbackLocation != "" {
		if !errors.Is(err, majordomo.ErrNotFound) {
			s.log.Debug().Err(err).Uint64("slot", uint64(slot)).Msg("Failed to obtain graffiti from primary location; using fallback")
		}
		data, err = s.majordomo.Fetch(ctx, s.fallbackLocation)
	}
	//	if err != nil && errors.Is(err, majordomo.ErrNotFound) {
	//		s.log.Trace().Uint64("slot", uint64(slot)).Msg("No graffiti obtained for proposer; using fallback")
	//		data, err = s.majordomo.Fetch(ctx, s.fallbackLocation)
	//	}
	if err != nil {
		if errors.Is(err, majordomo.ErrNotFound) {
			s.log.Debug().Uint64("slot", uint64(slot)).Msg("No graffiti obtained for proposer")
			return []byte{}, nil
		}
		s.log.Warn().Err(err).Msg("Failed to obtain graffiti")
		return nil, err
	}

	// Need to remove blank lines and handle both DOS style (\r\n) and Unix style (\n) newlines.
	graffitiLines := strings.Split(
		strings.TrimSpace(
			strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n", "\n"),
		),
		"\n")
	graffitiEntries := len(graffitiLines)
	if graffitiEntries == 0 {
		s.log.Debug().Msg("No graffiti available")
		return []byte{}, nil
	}

	// Pick a single line.  If multiple lines are available choose one at random.
	// #nosec G404
	graffitiIdx := rand.Intn(graffitiEntries)
	graffiti := graffitiLines[graffitiIdx]

	// Replace graffiti parameters with values.
	graffiti = strings.ReplaceAll(graffiti, "{{SLOT}}", fmt.Sprintf("%d", slot))
	graffiti = strings.ReplaceAll(graffiti, "{{VALIDATORINDEX}}", fmt.Sprintf("%d", validatorIndex))

	s.log.Trace().Str("graffiti", graffiti).Msg("Resolved graffiti")
	return []byte(graffiti), nil
}
