package testutil_test

import (
	"testing"

	"github.com/attestantio/vouch/testutil"
	"github.com/stretchr/testify/require"
)

func TestScenarioTestutil(t *testing.T) { require.Equal(t, 2, testutil.ScenarioTestutilOnlyTest()) }
