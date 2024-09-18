// Copyright © 2021 Attestant Limited.
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

// Package best is a strategy that obtains sync committee contributions
// from multiple nodes and selects the best one.
package best

import (
	"runtime"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                           zerolog.Level
	processConcurrency                 int64
	syncCommitteeContributionProviders map[string]eth2client.SyncCommitteeContributionProvider
	timeout                            time.Duration
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

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithSyncCommitteeContributionProviders sets the sync committee contribution providers.
func WithSyncCommitteeContributionProviders(providers map[string]eth2client.SyncCommitteeContributionProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionProviders = providers
	})
}

// WithTimeout sets the timeout for requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:           zerolog.GlobalLevel(),
		processConcurrency: int64(runtime.GOMAXPROCS(-1)),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if len(parameters.syncCommitteeContributionProviders) == 0 {
		return nil, errors.New("no sync committee contribution providers specified")
	}

	return &parameters, nil
}
