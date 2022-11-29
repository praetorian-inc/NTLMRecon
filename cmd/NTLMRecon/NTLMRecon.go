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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/NTLMRecon/pkg/NTLMRecon"
)

func main() {
	targetURL := flag.String("t", "", "the URL of the target to scan")
	outputMode := flag.String("o", "plaintext", "the output format of the data plaintext or JSON")

	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Error a target URL must be provided")
		flag.Usage()
		return
	}

	_, err := url.Parse(*targetURL)
	if err != nil {
		fmt.Printf("Error the specific target URL (%s) must be a valid URL\n", *targetURL)
		flag.Usage()
		return
	}

	if strings.ToLower(*outputMode) != "json" && strings.ToLower(*outputMode) != "plaintext" {
		fmt.Println("Error output mode should be either plaintext or json")
		flag.Usage()
		return
	}

	endpoints, err := NTLMRecon.BruteForceNTLMEndpoints(*targetURL)
	if err != nil {
		fmt.Printf("Error brute-forcing NTLM authentication endpoints (error: %s)\n", err)
	}

	for _, endpoint := range endpoints {

		if strings.ToLower(*outputMode) == "json" {
			jsonString, err := json.Marshal(endpoint)
			if err != nil {
				fmt.Println("Error marshalling JSON object: ", err)
				continue
			}

			fmt.Println(string(jsonString))
		} else {
			fmt.Println(endpoint.URL)
		}
	}
}
