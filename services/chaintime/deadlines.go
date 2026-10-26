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

package chaintime

import "time"

// GloasSlotDuration provides the slot duration in effect after Gloas.  Gloas serves this in
// milliseconds, and it can differ from SECONDS_PER_SLOT, so every Gloas-derived deadline must be a
// fraction of this value rather than of SECONDS_PER_SLOT.
func GloasSlotDuration(spec map[string]any, slotDuration time.Duration) time.Duration {
	if durationMS, ok := spec["SLOT_DURATION_MS"].(uint64); ok && durationMS != 0 {
		return time.Duration(durationMS) * time.Millisecond
	}

	return slotDuration
}

// DueBPS provides the deadline held in the named spec value, in basis points of the slot duration,
// falling back to the supplied default if the value is not served or is out of range.  The name is
// the exact key.  Gloas redefines the attestation and sync committee deadlines under
// _GLOAS-suffixed keys and keeps serving the unsuffixed keys for the slots before the fork, so
// reading the unsuffixed key after the fork would schedule duties to the deadlines it moved away
// from; the payload attestation deadline is new in Gloas and has no suffixed form.
func DueBPS(spec map[string]any, name string, slotDuration, fallback time.Duration) time.Duration {
	bps, ok := spec[name].(uint64)
	if !ok || bps == 0 || bps > 10000 {
		return fallback
	}

	return slotDuration * time.Duration(bps) / 10000
}
