// Copyright © 2020 Attestant Limited.
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
	"fmt"
	"net/http"
	"runtime"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	fetchConfig()

	initLogging()

	initProfiling()

	log.Info().Str("version", "v0.1.0").Msg("Starting vouch")
}

// fetchConfig fetches configuration from various sources.
func fetchConfig() {
	// Configuration.
	pflag.String("log-level", "info", "minimum level of messsages to log")
	pflag.String("profile-address", "", "Address on which to run profile server")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		panic(fmt.Sprintf("Failed to bind pflags to viper: %v", err))
	}

	cfgFile := ""
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			panic(fmt.Sprintf("Failed to obtain home directory: %v", err))
		}

		// Search config in home directory with name ".vouch" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".vouch")
	}

	viper.SetEnvPrefix("VOUCH")
	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(fmt.Sprintf("Failed to read configuration file: %v", err))
		}
	}
}

// initLogging initialises logging.
func initLogging() {
	if strings.ToLower(viper.GetString("log-level")) == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// initProfiling initialises the profiling server.
func initProfiling() {
	profileAddress := viper.GetString("profile-address")
	if profileAddress != "" {
		go func() {
			runtime.SetMutexProfileFraction(1)
			if err := http.ListenAndServe(profileAddress, nil); err != nil {
				log.Warn().Str("profileAddress", profileAddress).Err(err).Msg("Failed to start profile server")
			} else {
				log.Info().Str("profileAddress", profileAddress).Msg("Started profile server")
			}
		}()
	}
}
