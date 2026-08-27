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

// Package majority obtains payload attestation data from multiple nodes and selects the strongest agreement.
package majority

import (
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                        zerolog.Level
	clientMonitor                   metrics.ClientMonitor
	payloadAttestationDataProviders map[string]eth2client.PayloadAttestationDataProvider
	timeout                         time.Duration
	threshold                       int
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(parameters *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(parameters *parameters) {
	f(parameters)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.logLevel = logLevel })
}

// WithClientMonitor sets the client monitor for the service.
func WithClientMonitor(monitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.clientMonitor = monitor })
}

// WithPayloadAttestationDataProviders sets the payload attestation data providers.
func WithPayloadAttestationDataProviders(providers map[string]eth2client.PayloadAttestationDataProvider) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.payloadAttestationDataProviders = providers })
}

// WithTimeout sets the timeout for requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.timeout = timeout })
}

// WithThreshold sets the minimum number of matching valid responses.
func WithThreshold(threshold int) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.threshold = threshold })
}

func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := &parameters{
		logLevel:      zerolog.GlobalLevel(),
		clientMonitor: nullmetrics.New(),
		timeout:       time.Second,
	}
	for _, param := range params {
		if param != nil {
			param.apply(parameters)
		}
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if len(parameters.payloadAttestationDataProviders) == 0 {
		return nil, errors.New("no payload attestation data providers specified")
	}
	if parameters.timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if parameters.threshold < 0 {
		return nil, errors.New("threshold cannot be negative")
	}
	return parameters, nil
}
