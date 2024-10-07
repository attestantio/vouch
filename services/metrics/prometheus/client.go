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

package prometheus

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupClientMetrics() error {
	s.clientOperationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "client_operation",
		Name:      "requests_total",
	}, []string{"provider", "operation", "result"})
	if err := prometheus.Register(s.clientOperationCounter); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.clientOperationCounter = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.clientOperationTimer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "client_operation",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in client operations.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	}, []string{"provider", "operation"})
	if err := prometheus.Register(s.clientOperationTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.clientOperationTimer = alreadyRegisteredError.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			return err
		}
	}

	s.strategyOperationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "strategy_operation",
		Name:      "used_total",
		Help:      "The results used by a strategy.",
	}, []string{"strategy", "provider", "operation"})
	if err := prometheus.Register(s.strategyOperationCounter); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.strategyOperationCounter = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.strategyOperationTimer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "strategy_operation",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in strategy operations.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	}, []string{"strategy", "provider", "operation"})
	if err := prometheus.Register(s.strategyOperationTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.strategyOperationTimer = alreadyRegisteredError.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			return err
		}
	}

	return nil
}

// ClientOperation registers an operation.
func (s *Service) ClientOperation(provider string, operation string, succeeded bool, duration time.Duration) {
	address, err := parseAddress(provider)
	if err != nil && address != nil {
		provider = address.String()
	}
	if succeeded {
		s.clientOperationCounter.WithLabelValues(provider, operation, "succeeded").Add(1)
		s.clientOperationTimer.WithLabelValues(provider, operation).Observe(duration.Seconds())
	} else {
		s.clientOperationCounter.WithLabelValues(provider, operation, "failed").Add(1)
	}
}

// StrategyOperation provides a generic monitor for strategy operations.
func (s *Service) StrategyOperation(strategy string, provider string, operation string, duration time.Duration) {
	address, err := parseAddress(provider)
	if err != nil && address != nil {
		provider = address.String()
	}
	s.strategyOperationCounter.WithLabelValues(strategy, provider, operation).Add(1)
	s.strategyOperationTimer.WithLabelValues(strategy, provider, operation).Observe(duration.Seconds())
}

func parseAddress(address string) (*url.URL, error) {
	if !strings.HasPrefix(address, "http") {
		address = fmt.Sprintf("http://%s", address)
	}
	base, err := url.Parse(address)
	if err != nil {
		return nil, errors.Join(errors.New("invalid URL"), err)
	}
	// Remove any trailing slash from the path.
	base.Path = strings.TrimSuffix(base.Path, "/")

	// Attempt to mask any sensitive information in the URL, for logging purposes.
	baseAddress := *base
	if _, pwExists := baseAddress.User.Password(); pwExists {
		// Mask the password.
		user := baseAddress.User.Username()
		baseAddress.User = url.UserPassword(user, "xxxxx")
	}
	if baseAddress.Path != "" {
		// Mask the path.
		baseAddress.Path = "xxxxx"
	}
	if baseAddress.RawQuery != "" {
		// Mask all query values.
		sensitiveRegex := regexp.MustCompile("=([^&]*)(&)?")
		baseAddress.RawQuery = sensitiveRegex.ReplaceAllString(baseAddress.RawQuery, "=xxxxx$2")
	}

	return &baseAddress, nil
}
