// Copyright © 2020, 2022 Attestant Limited.
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

package logger

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// LogCapture allows testing code to query log output.
type LogCapture struct {
	mu      sync.Mutex
	entries []string
}

// NewLogCapture captures logs for querying.
func NewLogCapture() *LogCapture {
	c := &LogCapture{
		//entries: make([]*LogEntry, 0),
		entries: make([]string, 0),
	}
	zerologger.Logger = zerologger.Logger.Hook(c)
	return c
}

// Run is the hook to capture log entries.  It also stops the entry from being printed.
func (c *LogCapture) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, msg)
	e.Discard()
}

// AssertHasEntry checks if there is a log entry with the given string.
func (c *LogCapture) AssertHasEntry(t *testing.T, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.entries {
		if c.entries[i] == msg {
			return
		}
	}
	assert.Fail(t, fmt.Sprintf("Missing log message %q", msg), strings.Join(c.entries, "\n"))
}

// Entries returns all log entries.
func (c *LogCapture) Entries() []string {
	return c.entries
}

// ClearEntries removes all log entries.
func (c *LogCapture) ClearEntries() {
	c.entries = make([]string, 0)
}
