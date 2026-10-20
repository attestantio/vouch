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

package submitter

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/gloas"
)

// ProposerPreferencesSubmitter provides one result for submitting proposer preferences to each configured provider.
type ProposerPreferencesSubmitter interface {
	// SubmitProposerPreferences returns an entry for each provider; nil indicates acceptance.
	SubmitProposerPreferences(ctx context.Context, preferences []*gloas.SignedProposerPreferences, providers []string) map[string]error
}
