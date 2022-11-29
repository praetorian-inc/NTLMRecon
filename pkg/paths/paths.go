// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package paths

import (
	_ "embed"
	"strings"
)

//go:embed paths.txt
var paths string

func GetEmbeddedPaths() []string {
	var splitPathsFiltered []string

	splitPaths := strings.Split(paths, "\n")
	for _, a := range splitPaths {
		if a != "" {
			splitPathsFiltered = append(splitPathsFiltered, a)
		}
	}

	return splitPathsFiltered
}
