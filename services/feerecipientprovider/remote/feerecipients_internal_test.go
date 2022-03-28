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
	"os"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestFeeRecipientsFromRemoteNoCert(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("FEERECIPIENTS_TEST_URL") == "" {
		t.Skip("No FEERECIPIENTS_TEST_URL set; test not running")
	}

	feeRecipient := bellatrix.ExecutionAddress{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithBaseURL(os.Getenv("FEERECIPIENTS_TEST_URL")),
		WithDefaultFeeRecipient(feeRecipient),
	)
	require.NoError(t, err)

	_, err = s.fetchFeeRecipientsFromRemote(ctx, []phase0.ValidatorIndex{1, 2, 3})
	require.True(t, strings.Contains(err.Error(), "certificate signed by unknown authority"))
}

func TestFeeRecipientsFromRemote(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("FEERECIPIENTS_TEST_URL") == "" {
		t.Skip("No FEERECIPIENTS_TEST_URL set; test not running")
	}

	if os.Getenv("FEERECIPIENTS_TEST_CLIENT_CERT") == "" {
		t.Skip("No FEERECIPIENTS_TEST_CLIENT_CERT set; test not running")
	}

	feeRecipient := bellatrix.ExecutionAddress{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithBaseURL(os.Getenv("FEERECIPIENTS_TEST_URL")),
		WithDefaultFeeRecipient(feeRecipient),
		WithClientCert([]byte(os.Getenv("FEERECIPIENTS_TEST_CLIENT_CERT"))),
		WithClientKey([]byte(os.Getenv("FEERECIPIENTS_TEST_CLIENT_KEY"))),
		WithCACert([]byte(os.Getenv("FEERECIPIENTS_TEST_CA_CERT"))),
	)
	require.NoError(t, err)

	_, err = s.fetchFeeRecipientsFromRemote(ctx, []phase0.ValidatorIndex{1, 2, 3})
	require.NoError(t, err)
}
