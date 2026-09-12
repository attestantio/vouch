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

package beaconblockproposer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	// MetadataStrategy identifies the proposal strategy that selected a response.
	MetadataStrategy = "vouch.strategy"
	// MetadataProvider identifies the stable provider name that supplied a response.
	MetadataProvider = "vouch.provider"
	// MetadataSource identifies where the beacon node obtained the execution payload bid.
	MetadataSource = "vouch.source"
	// MetadataFallback reports that the strategy selected without a known value.
	MetadataFallback = "vouch.fallback"
)

var endpointInError = regexp.MustCompile(`(?i)(?:https?|grpc)://\S+`)

type requestIDContextKey struct{}

// EnsureRequestID returns a context carrying the proposal request ID and the ID itself.
func EnsureRequestID(ctx context.Context) (context.Context, string) {
	if requestID := RequestID(ctx); requestID != "" {
		return ctx, requestID
	}
	requestID := uuid.NewString()
	return context.WithValue(ctx, requestIDContextKey{}, requestID), requestID
}

// RequestID returns the proposal request ID carried by ctx.
func RequestID(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

// SafeError returns an error message with endpoint values removed.
func SafeError(err error, sensitiveValues ...string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, value := range sensitiveValues {
		if value != "" {
			message = strings.ReplaceAll(message, value, "<redacted>")
		}
	}
	return endpointInError.ReplaceAllString(message, "<redacted>")
}

// StableProviderName returns a stable telemetry name without exposing a configured endpoint.
func StableProviderName(provider string) string {
	if provider != "localhost" && !strings.ContainsAny(provider, ".:/@?#") {
		return provider
	}
	digest := sha256.Sum256([]byte(provider))
	return "provider-" + hex.EncodeToString(digest[:8])
}

// BuilderURLPresent reports whether response metadata contains a non-empty builder URL.
func BuilderURLPresent(metadata map[string]any) bool {
	for key, value := range metadata {
		if strings.EqualFold(key, "Eth-Builder-Url") {
			builderURL, isString := value.(string)
			return isString && builderURL != ""
		}
	}
	return false
}
