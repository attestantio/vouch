// Copyright © 2020 - 2024 Attestant Limited.
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

package mock

import (
	"context"

	builderapi "github.com/attestantio/go-builder-client/api"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type BuilderClient struct {
	MockPubkey *phase0.BLSPubKey
}

// Name returns the name of the builder implementation.
func (*BuilderClient) Name() string {
	return "mock"
}

// Address returns the address of the builder.
func (*BuilderClient) Address() string {
	return "mock:12345"
}

// Pubkey returns the public key of the builder (if any).
func (m *BuilderClient) Pubkey() *phase0.BLSPubKey {
	return m.MockPubkey
}

// BuilderBidProvider obtains a builder bid.
func (*BuilderClient) BuilderBid(_ context.Context,
	_ *builderapi.BuilderBidOpts,
) (
	*builderapi.Response[*builderspec.VersionedSignedBuilderBid],
	error,
) {
	return nil, nil
}
