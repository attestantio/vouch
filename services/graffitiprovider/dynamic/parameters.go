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
	"errors"

	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel  zerolog.Level
	location  string
	majordomo majordomo.Service
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

// WithLocation sets the location from which to fetch graffiti.
func WithLocation(location string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.location = location
	})
}

// WithMajordomo sets majordomo for the module.
func WithMajordomo(majordomo majordomo.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.majordomo = majordomo
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

	if parameters.majordomo == nil {
		return nil, errors.New("no majordomo specified")
	}
	if parameters.location == "" {
		return nil, errors.New("no location specified")
	}

	return &parameters, nil
}
