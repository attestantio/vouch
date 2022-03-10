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

package remote

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel            zerolog.Level
	monitor             metrics.Service
	baseURL             string
	clientCert          []byte
	clientKey           []byte
	caCert              []byte
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

// WithBaseURL sets the base URL for fetching fee recipients.
func WithBaseURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.baseURL = url
	})
}

// WithClientCert sets the bytes of the client TLS certificate.
func WithClientCert(cert []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientCert = cert
	})
}

// WithClientKey sets the bytes of the client TLS key.
func WithClientKey(key []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientKey = key
	})
}

// WithCACert sets the bytes of the certificate authority TLS certificate.
func WithCACert(cert []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCert = cert
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
	if parameters.baseURL == "" {
		return nil, errors.New("base URL not supplied")
	}
	url, err := url.Parse(parameters.baseURL)
	if err != nil {
		return nil, errors.New("base URL invalid")
	}
	if url.Scheme != "http" && url.Scheme != "https" {
		return nil, errors.New("invalid URL scheme")
	}
	url.Path = strings.TrimSuffix(url.Path, "/")
	parameters.baseURL = url.String()
	// client cert is optional.
	// client key is optional.
	// ca cert is optional.
	if parameters.defaultFeeRecipient == (bellatrix.ExecutionAddress{}) {
		return nil, errors.New("default fee recipient not supplied")
	}

	return &parameters, nil
}
