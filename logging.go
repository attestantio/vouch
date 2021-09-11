// Copyright © 2020, 2021 Attestant Limited.
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

package main

import (
	"os"

	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// log.
var log zerolog.Logger

// initLogging initialises logging.
func initLogging() error {
	// We set the global logging level to trace, because if the global log level is higher than the
	// local log level the local level is ignored.  It is then overridden for each module.
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	// Change the output file.
	if viper.GetString("log-file") != "" {
		f, err := os.OpenFile(resolvePath(viper.GetString("log-file")), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Wrap(err, "failed to open log file")
		}
		zerologger.Logger = zerologger.Logger.Output(f)
	}

	// Set the local logger from the global logger.
	log = zerologger.Logger.With().Logger().Level(util.LogLevel(""))

	return nil
}
