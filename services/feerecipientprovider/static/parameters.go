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

package static

import (
	"context"
	"errors"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel            zerolog.Level
	monitor             metrics.Service
	feeRecipients       map[phase0.ValidatorIndex]bellatrix.ExecutionAddress
	defaultFeeRecipient bellatrix.ExecutionAddress
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

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithFeeRecipients sets the fee recipients.
func WithFeeRecipients(feeRecipients map[phase0.ValidatorIndex]bellatrix.ExecutionAddress) Parameter {
	return parameterFunc(func(p *parameters) {
		p.feeRecipients = feeRecipients
	})
}

// WithDefaultFeeRecipient sets the default fee recipient.
func WithDefaultFeeRecipient(feeRecipient bellatrix.ExecutionAddress) Parameter {
	return parameterFunc(func(p *parameters) {
		p.defaultFeeRecipient = feeRecipient
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
		monitor:  nullmetrics.New(context.Background()),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("monitor not supplied")
	}
	if parameters.defaultFeeRecipient == (bellatrix.ExecutionAddress{}) {
		return nil, errors.New("default fee recipient not supplied")
	}

	return &parameters, nil
}
