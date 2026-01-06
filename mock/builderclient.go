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
	"errors"
	"fmt"
	"sync"
	"time"

	builderapi "github.com/attestantio/go-builder-client/api"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// BuilderClient is a mock.
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

// BuilderBid obtains a builder bid.
func (*BuilderClient) BuilderBid(_ context.Context,
	_ *builderapi.BuilderBidOpts,
) (
	*builderapi.Response[*builderspec.VersionedSignedBuilderBid],
	error,
) {
	return nil, nil
}

// CustomSubmitBlindedProposalProvider is a flexible mock that allows custom behavior.
type CustomSubmitBlindedProposalProvider struct {
	name       string
	address    string
	submitFunc func(context.Context, *builderapi.SubmitBlindedProposalOpts) error
	mu         sync.Mutex
	callCount  int
}

// NewCustomSubmitBlindedProposalProvider creates a new custom provider with configurable behavior.
func NewCustomSubmitBlindedProposalProvider(name, address string, submitFunc func(context.Context, *builderapi.SubmitBlindedProposalOpts) error) *CustomSubmitBlindedProposalProvider {
	return &CustomSubmitBlindedProposalProvider{
		name:       name,
		address:    address,
		submitFunc: submitFunc,
	}
}

// NewSubmitBlindedProposalProvider creates a simple mock that always succeeds.
func NewSubmitBlindedProposalProvider() *CustomSubmitBlindedProposalProvider {
	return NewCustomSubmitBlindedProposalProvider("mock-submit", "mock-submit:12345", func(_ context.Context, _ *builderapi.SubmitBlindedProposalOpts) error {
		return nil
	})
}

// Name returns the name of the provider.
func (m *CustomSubmitBlindedProposalProvider) Name() string {
	return m.name
}

// Address returns the address of the provider.
func (m *CustomSubmitBlindedProposalProvider) Address() string {
	return m.address
}

// Pubkey returns nil as this mock doesn't have a pubkey.
func (*CustomSubmitBlindedProposalProvider) Pubkey() *phase0.BLSPubKey {
	return nil
}

// BuilderBid returns nil as this mock is for submission only.
func (*CustomSubmitBlindedProposalProvider) BuilderBid(_ context.Context,
	_ *builderapi.BuilderBidOpts,
) (
	*builderapi.Response[*builderspec.VersionedSignedBuilderBid],
	error,
) {
	return nil, nil
}

// SubmitBlindedProposal submits a blinded proposal using the configured function.
func (m *CustomSubmitBlindedProposalProvider) SubmitBlindedProposal(ctx context.Context,
	opts *builderapi.SubmitBlindedProposalOpts,
) error {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	return m.submitFunc(ctx, opts)
}

// GetCallCount returns the number of times SubmitBlindedProposal was called.
func (m *CustomSubmitBlindedProposalProvider) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// NewErroringSubmitBlindedProposalProvider creates a provider that returns specific errors.
// Convenience constructor for common error scenarios.
func NewErroringSubmitBlindedProposalProvider(errorType string) *CustomSubmitBlindedProposalProvider {
	return NewCustomSubmitBlindedProposalProvider("mock-submit-error", "mock-submit-error:12345", func(ctx context.Context, _ *builderapi.SubmitBlindedProposalOpts) error {
		switch errorType {
		case "404":
			return errors.New("POST failed with status 404")
		case "400":
			return errors.New("POST failed with status 400")
		case "500":
			return errors.New("POST failed with status 500")
		case "timeout":
			<-ctx.Done()
			return ctx.Err()
		case "context_cancelled":
			return context.Canceled
		default:
			return fmt.Errorf("unknown error type: %s", errorType)
		}
	})
}

// NewSlowSubmitBlindedProposalProvider creates a provider that adds a delay before succeeding.
// Convenience constructor for testing concurrent behavior.
func NewSlowSubmitBlindedProposalProvider(delay time.Duration) *CustomSubmitBlindedProposalProvider {
	return NewCustomSubmitBlindedProposalProvider("mock-submit-slow", "mock-submit-slow:12345", func(_ context.Context, _ *builderapi.SubmitBlindedProposalOpts) error {
		time.Sleep(delay)
		return nil
	})
}

// CustomUnblindedProposalProvider is a flexible mock that allows custom behavior.
type CustomUnblindedProposalProvider struct {
	name        string
	address     string
	unblindFunc func(context.Context, *builderapi.UnblindProposalOpts) (*builderapi.Response[*consensusapi.VersionedSignedProposal], error)
	mu          sync.Mutex
	callCount   int
}

// NewCustomUnblindedProposalProvider creates a new custom provider with configurable behavior.
func NewCustomUnblindedProposalProvider(name, address string, unblindFunc func(context.Context, *builderapi.UnblindProposalOpts) (*builderapi.Response[*consensusapi.VersionedSignedProposal], error)) *CustomUnblindedProposalProvider {
	return &CustomUnblindedProposalProvider{
		name:        name,
		address:     address,
		unblindFunc: unblindFunc,
	}
}

// NewUnblindedProposalProvider creates a simple mock that returns a fixed response.
func NewUnblindedProposalProvider(response *consensusapi.VersionedSignedProposal) *CustomUnblindedProposalProvider {
	return NewCustomUnblindedProposalProvider("mock-unblind", "mock-unblind:12345", func(_ context.Context, _ *builderapi.UnblindProposalOpts) (*builderapi.Response[*consensusapi.VersionedSignedProposal], error) {
		return &builderapi.Response[*consensusapi.VersionedSignedProposal]{
			Data: response,
		}, nil
	})
}

// Name returns the name of the provider.
func (m *CustomUnblindedProposalProvider) Name() string {
	return m.name
}

// Address returns the address of the provider.
func (m *CustomUnblindedProposalProvider) Address() string {
	return m.address
}

// Pubkey returns nil as this mock doesn't have a pubkey.
func (*CustomUnblindedProposalProvider) Pubkey() *phase0.BLSPubKey {
	return nil
}

// BuilderBid returns nil as this mock is for unblinding only.
func (*CustomUnblindedProposalProvider) BuilderBid(_ context.Context,
	_ *builderapi.BuilderBidOpts,
) (
	*builderapi.Response[*builderspec.VersionedSignedBuilderBid],
	error,
) {
	return nil, nil
}

// UnblindProposal returns the unblinded proposal using the configured function.
func (m *CustomUnblindedProposalProvider) UnblindProposal(ctx context.Context,
	opts *builderapi.UnblindProposalOpts,
) (
	*builderapi.Response[*consensusapi.VersionedSignedProposal],
	error,
) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	return m.unblindFunc(ctx, opts)
}

// GetCallCount returns the number of times UnblindProposal was called.
func (m *CustomUnblindedProposalProvider) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// NewErroringUnblindedProposalProvider creates a provider that returns specific errors.
// Convenience constructor for common error scenarios.
func NewErroringUnblindedProposalProvider(errorType string) *CustomUnblindedProposalProvider {
	return NewCustomUnblindedProposalProvider("mock-unblind-error", "mock-unblind-error:12345", func(ctx context.Context, _ *builderapi.UnblindProposalOpts) (*builderapi.Response[*consensusapi.VersionedSignedProposal], error) {
		switch errorType {
		case "404":
			return nil, errors.New("POST failed with status 404")
		case "400":
			return nil, errors.New("POST failed with status 400")
		case "500":
			return nil, errors.New("POST failed with status 500")
		case "timeout":
			<-ctx.Done()
			return nil, ctx.Err()
		case "context_cancelled":
			return nil, context.Canceled
		default:
			return nil, fmt.Errorf("unknown error type: %s", errorType)
		}
	})
}

// NewSlowUnblindedProposalProvider creates a provider that adds a delay before returning.
// Convenience constructor for testing concurrent behavior.
func NewSlowUnblindedProposalProvider(response *consensusapi.VersionedSignedProposal, delay time.Duration) *CustomUnblindedProposalProvider {
	return NewCustomUnblindedProposalProvider("mock-unblind-slow", "mock-unblind-slow:12345", func(_ context.Context, _ *builderapi.UnblindProposalOpts) (*builderapi.Response[*consensusapi.VersionedSignedProposal], error) {
		time.Sleep(delay)
		return &builderapi.Response[*consensusapi.VersionedSignedProposal]{
			Data: response,
		}, nil
	})
}
