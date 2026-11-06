package mock_test

import (
	"testing"

	"github.com/attestantio/vouch/mock"
	"github.com/stretchr/testify/require"
)

func TestScenarioMock(t *testing.T) { require.Equal(t, 1, mock.ScenarioMockOnlyTest()) }
