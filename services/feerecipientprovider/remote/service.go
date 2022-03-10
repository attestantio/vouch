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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a fee recipient provider service.
type Service struct {
	baseURL             string
	client              *http.Client
	defaultFeeRecipient bellatrix.ExecutionAddress

	cache   map[phase0.ValidatorIndex]bellatrix.ExecutionAddress
	cacheMu sync.RWMutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new graffiti provider service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "feerecipientprovider").Str("impl", "remote").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	// Set up a client connection.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if len(parameters.clientCert) > 0 {
		log.Trace().Msg("Adding client certificate")
		cert, err := tls.X509KeyPair(parameters.clientCert, parameters.clientKey)
		if err != nil {
			return nil, errors.New("invalid client certificate or key")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if len(parameters.caCert) > 0 {
		log.Trace().Msg("Adding CA certificate")
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(parameters.caCert)
		tlsConfig.RootCAs = caCertPool
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	s := &Service{
		baseURL:             parameters.baseURL,
		client:              client,
		defaultFeeRecipient: parameters.defaultFeeRecipient,
		cache:               make(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress),
	}

	return s, nil
}
