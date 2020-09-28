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
	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupAccountManagerMetrics() error {
	s.accountManagerAccounts = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "accountmanager",
		Name:      "accounts_total",
		Help:      "The number of accounts managed by Vouch.",
	}, []string{"state"})
	if err := prometheus.Register(s.accountManagerAccounts); err != nil {
		return err
	}

	return nil
}

// Accounts sets the number of accounts in a given state.
func (s *Service) Accounts(state string, count uint64) {
	s.accountManagerAccounts.WithLabelValues(state).Set(float64(count))
}
