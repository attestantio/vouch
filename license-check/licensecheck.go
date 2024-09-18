// Copyright © 2024 Attestant Limited.
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
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	workingDir := "/Users/chrisberry/workspace/vouch/"
	licenseString := getLicenseString(workingDir)

	var files []string
	walkFunc := func(path string, info fs.DirEntry, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	}

	err := filepath.WalkDir(workingDir, walkFunc)
	if err != nil {
		log.Fatalf("failed to walk the path with %v", err)
	}
	for _, fileName := range files {
		err = updateFileWithLicense(fileName, licenseString)
		if err != nil {
			log.Fatalf("failed to update license file with %v", err)
		}
	}
}

func updateFileWithLicense(filePath, licenseString string) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	contents := string(file)
	newContents := licenseString

	header := true
	for _, line := range strings.Split(contents, "\n") {
		if !strings.HasPrefix(line, "//") {
			header = false
		}
		if !header {
			newContents += line + "\n"
		}
	}
	err = os.WriteFile(filePath, []byte(newContents), 0644)
	if err != nil {
		return err
	}
	return nil
}

func getLicenseString(workingDir string) string {
	licenseFilename := ".licenserc.json"
	file, err := os.ReadFile(filepath.Join(workingDir, licenseFilename))
	if err != nil {
		log.Fatalf("failed to read license file from: %s with: %v", licenseFilename, err)
	}

	jsonParsed := map[string][]string{}
	err = json.Unmarshal(file, &jsonParsed)
	if err != nil {
		log.Fatalf("failed to parse json from: %s with: %v", licenseFilename, err)
	}

	if len(jsonParsed) != 1 {
		log.Fatalf("failed to parse json from: %s with: %v", licenseFilename, err)
	}
	licenseString := ""
	for k, v := range jsonParsed {
		if strings.Contains(k, "go") {
			for _, line := range v {
				licenseString += line + "\n"
			}
		}
	}
	return licenseString
}
