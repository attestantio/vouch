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

package logger

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// LogCapture allows testing code to query log output.
type LogCapture struct {
	mu      sync.Mutex
	entries []map[string]interface{}
}

// Write captures an individual log message.
func (c *LogCapture) Write(p []byte) (int, error) {
	entry := make(map[string]interface{})
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
		entries: make([]map[string]interface{}, 0),
	}
	logger := zerolog.New(c)
	zerologger.Logger = logger
	return c
}

// AssertHasEntry checks if there is a log entry with the given string.
func (c *LogCapture) AssertHasEntry(t *testing.T, msg string) {
	t.Helper()
	if !c.HasLog(map[string]interface{}{
		"message": msg,
	}) {
		t.Logf("missing entry %q in log", msg)
		t.Fail()
	}
}

// HasLog returns true if there is a log entry with the matching fields.
func (c *LogCapture) HasLog(fields map[string]interface{}) bool {
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
//
//nolint:gocyclo
func (*LogCapture) hasField(entry map[string]interface{}, key string, value interface{}) bool {
	for entryKey, entryValue := range entry {
		if entryKey != key {
			continue
		}
		switch v := value.(type) {
		case bool:
			if entryValue == v {
				return true
			}
		case string:
			if entryValue == value.(string) {
				return true
			}
		case int:
			if int(entryValue.(float64)) == v {
				return true
			}
		case int8:
			if int8(entryValue.(float64)) == v {
				return true
			}
		case int16:
			if int16(entryValue.(float64)) == v {
				return true
			}
		case int32:
			if int32(entryValue.(float64)) == v {
				return true
			}
		case int64:
			if int64(entryValue.(float64)) == v {
				return true
			}
		case uint:
			if uint(entryValue.(float64)) == v {
				return true
			}
		case uint8:
			if uint8(entryValue.(float64)) == v {
				return true
			}
		case uint16:
			if uint16(entryValue.(float64)) == v {
				return true
			}
		case uint32:
			if uint32(entryValue.(float64)) == v {
				return true
			}
		case uint64:
			if uint64(entryValue.(float64)) == v {
				return true
			}
		case float32:
			if float32(entryValue.(float64)) == v {
				return true
			}
		case float64:
			if entryValue.(float64) == v {
				return true
			}
		default:
			panic("unhandled type")
		}
	}

	return false
}

// Entries returns all captures log entries.
func (c *LogCapture) Entries() []map[string]interface{} {
	return c.entries
}
