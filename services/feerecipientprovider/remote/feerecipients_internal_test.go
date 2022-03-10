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

	feeRecipient := bellatrix.ExecutionAddress{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithBaseURL(os.Getenv("FEERECIPIENTS_TEST_URL")),
		WithDefaultFeeRecipient(feeRecipient),
		// TODO make these environment variables.
		WithClientCert([]byte(`-----BEGIN CERTIFICATE-----
MIIFbzCCA1egAwIBAgIUSq5BEBEuDvEN7lg0t+zyLwwbq4cwDQYJKoZIhvcNAQEL
BQAwYDELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxv
bmRvbjEaMBgGA1UECgwRQXR0ZXN0YW50IExpbWl0ZWQxEjAQBgNVBAMMCUF0dGVz
dGFudDAeFw0yMTA2MTgxMzQwMDZaFw0yNjA2MTcxMzQwMDZaMCIxIDAeBgNVBAMM
F2JlYWNvbi1kMDEuYXR0ZXN0YW50LmlvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAnmgSEIWv38Nm+xyQZaMpizZGnM8nA0laAABTuLaXDn9D5LP6jtBz
5/ep2psgnvU9PE5iIkASn0FCCFw6Ud95TClZKUVTA0xTox3vq5Xqh0g5d48bGsaF
5GNJn2QvrQMErMqSpCQDnVNCsTghcjs/r2VIdGv8FfP4TTBqGD+B/3nO3suU2hbw
QL1d1YMcmMLMyPgOR5/L+Ui8UvwpO4BAsfUakWyM9/bRwwaAfLdXSt4PoFcZhWmK
SyhC9v+VcrOJj3vWuztVyDS3R3k5awMBPr0AOea8U0m/VMFyrnGD4+Cth5+WXrnd
QX4Q4wZMBqP92MTggTHN3YuvAjD0Oqz2HXCxE+YHJeYOdt45GTmEM5JYxoHduShc
vK4fLlnLbBLcABRVaVwni63p/H5I21hutzWFNkRUGQ4JBzESbEjYJzT3/3QoJO83
eAgbugQxMY5wtcFRCUaSbiljD7d91WH2+yiU626m8aW9Ywe6+1u25+0tAS4Wlmvl
fO9NtauyliFJ6TrMBOAeKJjMNEEkI+hrdLyDg/+aFu+5KIpg0V97+kDoyPhz6LFS
jstZX/I5lGmI+w2hbJv3LC9+ZpYVB7pxcEC8C/GIon5nk4vudgysxNelAO/J8PV1
6buj4KpqcdKPkqE9+ZuzcOLai5hIv2tuQH92jprxriM7eYBSamLKkPsCAwEAAaNf
MF0wHwYDVR0jBBgwFoAUL0O7oRZHoQU6nLy8uOm0X9GfrT8wCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwIgYDVR0RBBswGYIXYmVhY29uLWQwMS5hdHRlc3RhbnQuaW8w
DQYJKoZIhvcNAQELBQADggIBAKw2b3tqlibiCLNLul+ApyfmhZ5v7Thcv6Jda1N/
AIsIIX/rw4fO3+VbgFuUvcSjvzuwXZ9uKVVKLArfGVNOaOWAwN6z3x+noN8jRyX+
ofKaFACZJN6jawaNl1FlWDGMdT9VDzIqeiB1PkVFcez5DIRM1Yawm8Wu3X3aWWUY
SX3bMV+qy/tSqlcsQYRbCnBLK41WK8aoZa53eOTuvO11OIb/che55KUyIRoe3M0i
K8SuMUlsQ1sQeWiFpYj5mSr4fdC0xaB5hDS9NlgQKqKNQxtPNF9d/fSLnc9zGllV
gvzqCBxcMv42F9Qyqi52p3XmghdRwDCmwU8roFzz50t47B7sQoB4Qwqh558YSCCg
qtEyegdBSb2lq8hwmBH7+hWmpzS9vEnL3FN1issJr5UXiavp67t9qKISeeATi2AA
zPbL/ma+MfOR6AR1nxvPq4qLt6UEfyu+CzURP9Q7zqq64vqDpEQFHAPdwBJpVA1J
4EKLx3s7RdDWAbg8G9Ph5DT1XOTtxyVUx2Lm5m6SUDD4SRdz0Ga2yhCXJSBRlcFY
JYRN7vMm1sbqlSEx6XX/EW7RbyHKfL5oIAAftUneTz6ZoB3Q6gglPDu2dT8iIdey
l2t54GlqfhDtZpyRi0FHcC9KJ+VwAqoZgY2iUQ6yQ8TpqVRXaBB850gH3Lr/orSS
eoYo
-----END CERTIFICATE-----`)),

		WithClientKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)),
		WithCACert([]byte(`-----BEGIN CERTIFICATE-----
MIIFoTCCA4mgAwIBAgIUJcYDjBEL6T42GohYUQ3DJnZjMbwwDQYJKoZIhvcNAQEL
BQAwYDELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxv
bmRvbjEaMBgGA1UECgwRQXR0ZXN0YW50IExpbWl0ZWQxEjAQBgNVBAMMCUF0dGVz
dGFudDAeFw0yMDExMTgxMDEwNTNaFw0yNTExMTcxMDEwNTNaMGAxCzAJBgNVBAYT
AkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xGjAYBgNVBAoM
EUF0dGVzdGFudCBMaW1pdGVkMRIwEAYDVQQDDAlBdHRlc3RhbnQwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQDpYXhpAYdmbu65oLqsmsgu0GJGmfrKciNw
weETx0lXsGyQDx1YVpuoA1TcS35KDnORd82mCHMHzLb4h0leqpxQswOIPAOVQIc1
xKp4GETPyMPQjZ1v5b9tw+Zi0KOxA4s1I/sxb3Jc178GGufBh+VGZUyV+MkfPQT7
XMRijBBuVcdK8Z/k9dWkneBohCy5ejYuXdGwKdAt+SpcHB94DetL5jfGimCUQuFq
8Vnd/jv2OOycGNLQGU95CyiUX9vRbjkF+E/SeTxtKP4t3ObNjifbJfjaumr2XrN8
xx03TMnAZzSe6OOGVALTnX/7W9cUgulziURMHtU+gJJs3jjlHYIKKqJm2Yo1540q
SAsoEzal3Dt6ebt8hp0qbOqaug1HtMS0QO6pfFX414qEAVSTYdQ/tnyIC9q8XSAM
BrFr5Hx+fp2GWCEycFUoQiLzWkMc9IE+b17DgihvU0oM4aoYkxxkurnioyxI73hz
ATzhko+fhwEHyPbhpoHQyuRVk4/Go2oTl6h4c9xOz7krov4m811o0ao1M082Gozf
VgQwhxnNibVURZVIsQYDw/G4++RJ+nS+2Eaf7Ps16lBudyGJyWEK4EHiqSuy7Tmy
p+eaxB09QuEigEuQfrX2AY65eZ/0u30I8PwEv1jPrNcmio5qoT4Dz6nt7cKjBqVr
i2C7Cq/8awIDAQABo1MwUTAdBgNVHQ4EFgQUL0O7oRZHoQU6nLy8uOm0X9GfrT8w
HwYDVR0jBBgwFoAUL0O7oRZHoQU6nLy8uOm0X9GfrT8wDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAgEAFjBvyRBxe9SKwip+MlQormU0kGyupCHHoOt0
nWu8/QoLWbMXO9lhmekmMUFvBMx6EXFCW+XjJjKzRsvdPMVrGKBDfD1ZIe+DAHbN
9B/ZOVoOC27E2HM0N9NUwxavnbDdrPeSFkFQvF5P7E5uE1uMQzr5OzW3EJe1oF9j
cQWZGCl4AdoCsAPFeuYkorXQOEwOtmWbb8spWPNtqF2+i3KM503bgI0BXAC7kN+0
+X+tE6tSa7S3auQnVC1olSgTV6Z+Gtoiruqu0ijN/sgG+Uze/Z8xSXBRdcMBnAMN
mCfscZd86q92goheJgM0jJIjJeLmzECBHaKpTMqyeBVqjn3r/19eZltphAwIMyYw
ac0+JjXKD9K/k2QdwlNa6S4yXGTA4AlVes9cQ3i1YfFyfsek1FatHcO4IOEA/ZRM
VXVWxLHNOqPr+R8Pzo30bGT2qq3X3t+nHYLVUNlzjrzzHstEO0vz32n9Qhbeq6d2
l42WC9M/JDX29tGn1WWfLe6bb1sqWML4mVj0yqIGWv0oE9SgqEoGaP11/WnOjN7R
BgkeA21rohButq+TikwRmzbXfnzo6McoIi2mxK3e68DBSM5v2x+oucG1ZFb6TttB
CYKVEhYeP5zrqYviP65lhEQ3tKigJl8fpeXkkjJR7VN68AuMAJrvYAKs4rbYy8X1
ZG2F6CI=
-----END CERTIFICATE-----`)),
	)
	require.NoError(t, err)

	_, err = s.fetchFeeRecipientsFromRemote(ctx, []phase0.ValidatorIndex{1, 2, 3})
	require.NoError(t, err)
}
