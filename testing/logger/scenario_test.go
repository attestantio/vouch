package logger_test

import (
	"testing"

	"github.com/attestantio/vouch/testing/logger"
	"github.com/stretchr/testify/require"
)

func TestScenarioLogger(t *testing.T) { require.Equal(t, 3, logger.NewLogCapture().ScenarioCount()) }
