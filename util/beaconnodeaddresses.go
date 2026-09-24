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

package util

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

// BeaconNodeName identifies a configured beacon node without exposing its address.
func BeaconNodeName(address string) string {
	if name, ok := LookupBeaconNodeName(address); ok {
		return name
	}
	if address != "localhost" && !strings.ContainsAny(address, ".:/@?#") {
		return address
	}
	return "beacon-unknown"
}

// LookupBeaconNodeName returns the identity of a configured beacon node, if present.
func LookupBeaconNodeName(address string) (string, bool) {
	addresses := BeaconNodeTelemetryAddresses()
	for i, configured := range addresses {
		if configured == address {
			return fmt.Sprintf("beacon-%d", i+1), true
		}
	}
	requestedHost := beaconNodeHost(address)
	if requestedHost == "" {
		return "", false
	}
	index := -1
	for i, configured := range addresses {
		if beaconNodeHost(configured) == requestedHost {
			if index != -1 {
				return "beacon-unknown", true
			}
			index = i
		}
	}
	if index == -1 {
		return "", false
	}
	return fmt.Sprintf("beacon-%d", index+1), true
}

func beaconNodeHost(address string) string {
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// BeaconNodeTelemetryAddresses lists configured beacon nodes in stable configuration order.
func BeaconNodeTelemetryAddresses() []string {
	addresses := append([]string(nil), BeaconNodeAddresses("")...)
	var collect func(map[string]any)
	collect = func(settings map[string]any) {
		keys := make([]string, 0, len(settings))
		for key := range settings {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			switch value := settings[key].(type) {
			case map[string]any:
				collect(value)
			case []string:
				if key == "beacon-node-addresses" {
					addresses = append(addresses, value...)
				}
			case []any:
				if key == "beacon-node-addresses" {
					for _, address := range value {
						if address, ok := address.(string); ok {
							addresses = append(addresses, address)
						}
					}
				}
			case string:
				if key == "beacon-node-address" && value != "" {
					addresses = append(addresses, value)
				}
			}
		}
	}
	collect(viper.AllSettings())
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, configured := range addresses {
		if _, exists := seen[configured]; exists {
			continue
		}
		seen[configured] = struct{}{}
		result = append(result, configured)
	}
	return result
}

// BeaconNodeLogWriter replaces configured addresses in log output with their identities.
func BeaconNodeLogWriter(writer io.Writer) io.Writer {
	addresses := BeaconNodeTelemetryAddresses()
	hostCounts := make(map[string]int, len(addresses))
	for _, address := range addresses {
		hostCounts[beaconNodeHost(address)]++
	}
	aliases := make(map[string]string, len(addresses)*4)
	for i, address := range addresses {
		name := fmt.Sprintf("beacon-%d", i+1)
		aliases[address] = name
		if host := beaconNodeHost(address); host != "" {
			if hostCounts[host] > 1 {
				name = "beacon-unknown"
			}
			aliases["http://"+host] = name
			aliases["https://"+host] = name
			aliases[host] = name
			if parsed, err := url.Parse(address); err == nil && parsed.User != nil {
				credentials := parsed.User.String() + "@" + host
				aliases["http://"+credentials] = name
				aliases["https://"+credentials] = name
				if _, hasPassword := parsed.User.Password(); hasPassword {
					masked := url.UserPassword(parsed.User.Username(), "xxxxx").String() + "@" + host
					aliases["http://"+masked] = name
					aliases["https://"+masked] = name
				}
			}
		}
	}
	ordered := make([]string, 0, len(aliases))
	for address := range aliases {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	pairs := make([]string, 0, len(ordered)*2)
	for _, address := range ordered {
		pairs = append(pairs, address, aliases[address])
	}
	if len(pairs) == 0 {
		return writer
	}
	return &beaconNodeLogWriter{writer: writer, replacer: strings.NewReplacer(pairs...)}
}

var beaconNodeLogCredentials = regexp.MustCompile(`https?://[^\s"\\/@]+@(beacon-(?:[0-9]+|unknown))`)
var beaconNodeLogSuffix = regexp.MustCompile(`(beacon-(?:[0-9]+|unknown))[/?#][^\s"\\]*`)

type beaconNodeLogWriter struct {
	writer   io.Writer
	replacer *strings.Replacer
}

func (w *beaconNodeLogWriter) Write(p []byte) (int, error) {
	redacted := beaconNodeLogCredentials.ReplaceAllString(w.replacer.Replace(string(p)), "$1")
	redacted = beaconNodeLogSuffix.ReplaceAllString(redacted, "$1")
	n, err := io.WriteString(w.writer, redacted)
	if err != nil {
		return 0, err
	}
	if n != len(redacted) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// BeaconNodeAddresses returns the best beacon node addresses for the path.
func BeaconNodeAddresses(path string) []string {
	if path == "" {
		if viper.GetStringSlice("beacon-node-addresses") != nil {
			return viper.GetStringSlice("beacon-node-addresses")
		}
		return viper.GetStringSlice("beacon-node-address")
	}

	key := fmt.Sprintf("%s.beacon-node-addresses", path)
	if len(viper.GetStringSlice(key)) > 0 {
		return viper.GetStringSlice(key)
	}
	// Lop off the child and try again.
	lastPeriod := strings.LastIndex(path, ".")
	if lastPeriod == -1 {
		return BeaconNodeAddresses("")
	}
	return BeaconNodeAddresses(path[0:lastPeriod])
}
