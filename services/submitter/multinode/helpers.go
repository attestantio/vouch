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

package multinode

import (
	"context"
	"strings"

	eth2client "github.com/attestantio/go-eth2-client"
)

// serviceInfo returns the service name and provider information.
func (*Service) serviceInfo(ctx context.Context, submitter interface{}) (string, string) {
	serviceName := "<unknown>"
	provider := "<unknown>"
	if service, isService := submitter.(eth2client.Service); isService {
		provider = service.Address()
	}
	if service, isService := submitter.(eth2client.NodeVersionProvider); isService {
		nodeVersion, err := service.NodeVersion(ctx)
		if err == nil {
			switch {
			case strings.Contains(strings.ToLower(nodeVersion), "lighthouse"):
				serviceName = "lighthouse"
			case strings.Contains(strings.ToLower(nodeVersion), "prysm"):
				serviceName = "prysm"
			case strings.Contains(strings.ToLower(nodeVersion), "teku"):
				serviceName = "teku"
			case strings.Contains(strings.ToLower(nodeVersion), "nimbus"):
				serviceName = "nimbus"
			}
		}
	}

	return serviceName, provider
}
