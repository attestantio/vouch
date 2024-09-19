// Copyright © 2024 Attestant Limited.
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

package blockrelay

import (
	"encoding/json"
	"fmt"

	v1 "github.com/attestantio/vouch/services/blockrelay/v1"
	v2 "github.com/attestantio/vouch/services/blockrelay/v2"
	"github.com/pkg/errors"
)

type executionConfigMetadataJSON struct {
	Version int `json:"version"`
}

// UnmarshalJSON unmarshals an execution configurator.
func UnmarshalJSON(data []byte) (ExecutionConfigurator, error) {
	var metadata executionConfigMetadataJSON
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal metadata")
	}

	switch metadata.Version {
	case 0:
		var execConfigV1 v1.ExecutionConfig
		if err := json.Unmarshal(data, &execConfigV1); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal unversioned execution config")
		}
		return &execConfigV1, nil
	case 2:
		var execConfigV2 v2.ExecutionConfig
		if err := json.Unmarshal(data, &execConfigV2); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal version 2 execution config")
		}
		return &execConfigV2, nil
	default:
		return nil, fmt.Errorf("unhandled execution config version %d", metadata.Version)
	}
}
