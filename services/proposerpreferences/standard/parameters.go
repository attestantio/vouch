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
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
)

type parameters struct {
	monitor   metrics.Service
	signer    signer.ProposerPreferencesSigner
	submitter submitter.ProposerPreferencesSubmitter
}

// Parameter is a parameter for the service.
type Parameter interface {
	apply(parameters *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(parameters *parameters) {
	f(parameters)
}

// WithMonitor sets the metrics monitor.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.monitor = monitor })
}

// WithSigner sets the proposer-preferences signer.
func WithSigner(signer signer.ProposerPreferencesSigner) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.signer = signer })
}

// WithSubmitter sets the proposer-preferences submitter.
func WithSubmitter(submitter submitter.ProposerPreferencesSubmitter) Parameter {
	return parameterFunc(func(parameters *parameters) { parameters.submitter = submitter })
}

func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := &parameters{}
	for _, param := range params {
		if param != nil {
			param.apply(parameters)
		}
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.signer == nil {
		return nil, errors.New("no signer specified")
	}
	if parameters.submitter == nil {
		return nil, errors.New("no submitter specified")
	}

	return parameters, nil
}
