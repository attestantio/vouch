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

package standard

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel              zerolog.Level
	genesisTimeProvider   eth2client.GenesisTimeProvider
	slotDurationProvider  eth2client.SlotDurationProvider
	slotsPerEpochProvider eth2client.SlotsPerEpochProvider
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithGenesisTimeProvider sets the genesis time provider.
func WithGenesisTimeProvider(provider eth2client.GenesisTimeProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.genesisTimeProvider = provider
	})
}

// WithSlotDurationProvider sets the seconds per slot provider.
func WithSlotDurationProvider(provider eth2client.SlotDurationProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotDurationProvider = provider
	})
}

// WithSlotsPerEpochProvider sets the slots per epoch provider.
func WithSlotsPerEpochProvider(provider eth2client.SlotsPerEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotsPerEpochProvider = provider
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.genesisTimeProvider == nil {
		return nil, errors.New("no genesis time provider specified")
	}
	if parameters.slotDurationProvider == nil {
		return nil, errors.New("no slot duration provider specified")
	}
	if parameters.slotsPerEpochProvider == nil {
		return nil, errors.New("no slots per epoch provider specified")
	}

	return &parameters, nil
}
