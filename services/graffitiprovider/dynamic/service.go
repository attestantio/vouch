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
	location  string
	majordomo majordomo.Service
}

// module-wide log.
var log zerolog.Logger

// New creates a new graffiti provider service.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "graffitiprovider").Str("impl", "dynamic").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		location:  parameters.location,
		majordomo: parameters.majordomo,
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
	log.Trace().Str("location", location).Msg("Resolved graffiti location")

	// Fetch data from location.
	locationData, err := s.majordomo.Fetch(ctx, location)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch graffiti")
		return nil, err
	}

	// Need to remove blank lines and handle both DOS style (\r\n) and Unix style (\n) newlines.
	graffitiLines := strings.Split(
		strings.TrimSpace(
			strings.ReplaceAll(strings.ReplaceAll(string(locationData), "\r\n", "\n"), "\n\n", "\n"),
		),
		"\n")
	graffitiEntries := len(graffitiLines)
	if graffitiEntries == 0 {
		log.Debug().Msg("No graffiti found")
		return []byte{}, nil
	}

	// Pick a single line.  If multiple lines are available choose one at random.
	// #nosec G404
	graffitiIdx := rand.Intn(graffitiEntries)
	graffiti := graffitiLines[graffitiIdx]

	// Replace graffiti parameters with values.
	graffiti = strings.ReplaceAll(graffiti, "{{SLOT}}", fmt.Sprintf("%d", slot))
	graffiti = strings.ReplaceAll(graffiti, "{{VALIDATORINDEX}}", fmt.Sprintf("%d", validatorIndex))

	log.Trace().Str("graffiti", graffiti).Msg("Resolved graffiti")
	return []byte(graffiti), nil
}
