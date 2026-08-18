// Copyright © 2022 - 2026 Attestant Limited.
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
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// LogCapture allows testing code to query log output.
type LogCapture struct {
	entries []map[string]any
	mu      sync.Mutex
}

// Write captures an individual log message.
func (c *LogCapture) Write(p []byte) (int, error) {
	entry := make(map[string]any)
	err := json.Unmarshal(p, &entry)
	if err != nil {
		return -1, err
	}
	c.mu.Lock()
	c.entries = append(c.entries, entry)
	c.mu.Unlock()
	return len(p), nil
}

// NewLogCapture captures logs for querying.
// Logs are created in JSON format and without timestamps.
func NewLogCapture() *LogCapture {
	c := &LogCapture{
		entries: make([]map[string]any, 0),
	}
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	logger := zerolog.New(c).Level(zerolog.TraceLevel)
	zerologger.Logger = logger
	return c
}

// AssertHasEntry checks if there is a log entry with the given string.
func (c *LogCapture) AssertHasEntry(t *testing.T, msg string) {
	t.Helper()
	if !c.HasLog(map[string]any{
		"message": msg,
	}) {
		t.Logf("missing entry %q in log", msg)
		t.Fail()
	}
}

// HasLog returns true if there is a log entry with the matching fields.
func (c *LogCapture) HasLog(fields map[string]any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	var matched bool
	for i := range c.entries {
		matches := 0
		for key, value := range fields {
			if c.hasField(c.entries[i], key, value) {
				matches++
			}
		}
		if matches == len(fields) {
			matched = true
			break
		}
	}
	return matched
}

// hasField returns true if the entry has a matching field.
func (*LogCapture) hasField(entry map[string]any, key string, value any) bool {
	entryValue, exists := entry[key]
	if !exists {
		return false
	}

	return fieldsMatch(entryValue, value)
}

func fieldsMatch(entryValue any, value any) bool {
	expected := reflect.ValueOf(value)
	if expected.CanInt() {
		return int64(entryValue.(float64)) == expected.Int()
	}
	if expected.CanUint() {
		return uint64(entryValue.(float64)) == expected.Uint()
	}
	if expected.CanFloat() {
		return entryValue.(float64) == expected.Float()
	}

	switch value.(type) {
	case bool, string:
		return entryValue == value
	default:
		panic("unhandled type")
	}
}

// Entries returns all captures log entries.
func (c *LogCapture) Entries() []map[string]any {
	return c.entries
}
