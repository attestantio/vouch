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
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	monitor                             metrics.Service
	payloadAttestationDataProvider      eth2client.PayloadAttestationDataProvider
	payloadAttestationDataSigner        signer.PayloadAttestationDataSigner
	payloadAttestationMessagesSubmitter submitter.PayloadAttestationMessagesSubmitter
	logLevel                            zerolog.Level
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) { p.logLevel = logLevel })
}

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) { p.monitor = monitor })
}

// WithPayloadAttestationDataProvider sets the payload attestation data provider.
func WithPayloadAttestationDataProvider(provider eth2client.PayloadAttestationDataProvider) Parameter {
	return parameterFunc(func(p *parameters) { p.payloadAttestationDataProvider = provider })
}

// WithPayloadAttestationDataSigner sets the payload attestation data signer.
func WithPayloadAttestationDataSigner(signer signer.PayloadAttestationDataSigner) Parameter {
	return parameterFunc(func(p *parameters) { p.payloadAttestationDataSigner = signer })
}

// WithPayloadAttestationMessagesSubmitter sets the payload attestation messages submitter.
func WithPayloadAttestationMessagesSubmitter(submitter submitter.PayloadAttestationMessagesSubmitter) Parameter {
	return parameterFunc(func(p *parameters) { p.payloadAttestationMessagesSubmitter = submitter })
}

func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := &parameters{logLevel: zerolog.GlobalLevel()}
	for _, p := range params {
		if p != nil {
			p.apply(parameters)
		}
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.payloadAttestationDataProvider == nil {
		return nil, errors.New("no payload attestation data provider specified")
	}
	if parameters.payloadAttestationDataSigner == nil {
		return nil, errors.New("no payload attestation data signer specified")
	}
	if parameters.payloadAttestationMessagesSubmitter == nil {
		return nil, errors.New("no payload attestation messages submitter specified")
	}
	return parameters, nil
}
