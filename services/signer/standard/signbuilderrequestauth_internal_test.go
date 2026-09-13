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

package standard

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestSignBuilderRequestAuthRejectsNilAuth(t *testing.T) {
	signature, err := (&Service{}).SignBuilderRequestAuth(context.Background(), &recordingBuilderAuthAccount{}, nil)
	require.Equal(t, phase0.BLSSignature{}, signature)
	require.EqualError(t, err, "no builder request authorization supplied")
}

func TestSignBuilderRequestAuthUsesGenericSigner(t *testing.T) {
	auth := &gloas.BuilderRequestAuth{Data: []byte{0x12, 0x34}, Slot: 42}
	root, err := auth.HashTreeRoot()
	require.NoError(t, err)
	account := &recordingBuilderAuthAccount{}

	signature, err := (&Service{}).SignBuilderRequestAuth(context.Background(), account, auth)
	require.NoError(t, err)
	require.Equal(t, phase0.BLSSignature{0x99}, signature)
	require.Equal(t, root[:], account.data)
	require.Equal(t, []byte{0x0b, 0x00, 0x00, 0x01}, account.domain[:4])
	require.Equal(t, make([]byte, 28), account.domain[4:])
	require.Equal(t, 1, account.calls)
}

type recordingBuilderAuthAccount struct {
	data   []byte
	domain []byte
	calls  int
}

func (*recordingBuilderAuthAccount) ID() uuid.UUID { return uuid.Nil }
func (*recordingBuilderAuthAccount) Name() string  { return "builder-auth" }
func (*recordingBuilderAuthAccount) PublicKey() e2types.PublicKey {
	return nil
}
func (a *recordingBuilderAuthAccount) SignGeneric(_ context.Context, data []byte, domain []byte) (e2types.Signature, error) {
	a.calls++
	a.data = append([]byte(nil), data...)
	a.domain = append([]byte(nil), domain...)

	return builderAuthSignature{}, nil
}
func (*recordingBuilderAuthAccount) SignBeaconProposal(context.Context, uint64, uint64, []byte, []byte, []byte, []byte) (e2types.Signature, error) {
	return nil, nil
}
func (*recordingBuilderAuthAccount) SignBeaconAttestation(context.Context, uint64, uint64, []byte, uint64, []byte, uint64, []byte, []byte) (e2types.Signature, error) {
	return nil, nil
}

var _ e2wtypes.AccountProtectingSigner = (*recordingBuilderAuthAccount)(nil)

type builderAuthSignature struct{}

func (builderAuthSignature) Verify([]byte, e2types.PublicKey) bool                  { return false }
func (builderAuthSignature) VerifyAggregate([][]byte, []e2types.PublicKey) bool     { return false }
func (builderAuthSignature) VerifyAggregateCommon([]byte, []e2types.PublicKey) bool { return false }
func (builderAuthSignature) Marshal() []byte                                        { return append([]byte{0x99}, make([]byte, 95)...) }
