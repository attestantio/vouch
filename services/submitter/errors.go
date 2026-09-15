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

package submitter

import "errors"

// SubmissionErrors contains errors returned by individual submitters.
type SubmissionErrors struct {
	errors []error
}

// NewSubmissionErrors creates an aggregate of individual submission errors.
func NewSubmissionErrors(errs ...error) *SubmissionErrors {
	return &SubmissionErrors{errors: errs}
}

// Error returns the combined submission error messages.
func (e *SubmissionErrors) Error() string {
	return errors.Join(e.errors...).Error()
}

// Unwrap returns the individual submission errors.
func (e *SubmissionErrors) Unwrap() []error {
	return e.errors
}
