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

package standard

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel           zerolog.Level
	monitor            metrics.ValidatorsManagerMonitor
	clientMonitor      metrics.ClientMonitor
	validatorsProvider eth2client.ValidatorsProvider
	farFutureEpoch     phase0.Epoch
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
func WithMonitor(monitor metrics.ValidatorsManagerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithClientMonitor sets the client monitor for the module.
func WithClientMonitor(clientMonitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientMonitor = clientMonitor
	})
}

// WithValidatorsProvider sets the validator status provider.
func WithValidatorsProvider(provider eth2client.ValidatorsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorsProvider = provider
	})
}

// WithFarFutureEpoch sets the far future epoch.
func WithFarFutureEpoch(farFutureEpoch phase0.Epoch) Parameter {
	return parameterFunc(func(p *parameters) {
		p.farFutureEpoch = farFutureEpoch
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:      zerolog.GlobalLevel(),
		monitor:       nullmetrics.New(),
		clientMonitor: nullmetrics.New(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if parameters.validatorsProvider == nil {
		return nil, errors.New("no validators provider specified")
	}
	if parameters.farFutureEpoch == 0 {
		return nil, errors.New("no far future epoch specified")
	}

	return &parameters, nil
}
