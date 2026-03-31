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

package NTLMRecon

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/NTLMRecon/internal/ntlm"
	"github.com/praetorian-inc/NTLMRecon/pkg/paths"
	"github.com/praetorian-inc/NTLMRecon/pkg/structs"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/retryablehttp-go"
)

const (
	// A minimal NTLM_NEGOTIATE packet for NTLM
	MinimalNegotiatePacket = "TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="
)

func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func BruteForceNTLMEndpoints(targetURL string, hostHeader string, debug bool) ([]structs.NTLMReconOutput, error) {
	var endpoints []structs.NTLMReconOutput

	ntlmAppPaths := paths.GetEmbeddedPaths()

	if len(ntlmAppPaths) == 0 {
		return endpoints, fmt.Errorf("included wordlist is empty")
	}
	
	if debug {
		fmt.Printf("[DEBUG] Testing %d paths against target %s\n", len(ntlmAppPaths), targetURL)
		if hostHeader != "" {
			fmt.Printf("[DEBUG] Using Host header: %s\n", hostHeader)
		}
	}

	url, err := url.Parse(targetURL)
	if err != nil {
		fmt.Println("Error parsing target URL: ", err)
		return endpoints, fmt.Errorf("unable to parse the provided target URL: %s", err)
	}

	fastdialerInstance, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return endpoints, err
	}
	defer fastdialerInstance.Close()

	for i, ntlmAppPath := range ntlmAppPaths {
		var endpoint structs.NTLMReconOutput

		guessURL := url.Scheme + "://" + url.Host + ntlmAppPath
		if debug {
			fmt.Printf("[DEBUG] [%d/%d] Testing: %s\n", i+1, len(ntlmAppPaths), guessURL)
		}
		
		// First, try a request without authentication to see if NTLM is offered
		req, err := retryablehttp.NewRequest("GET", guessURL, nil)
		if err != nil {
			fmt.Println("Error creating HTTP request: ", err)
			return endpoints, fmt.Errorf("unable to create HTTP request: %s", err)
		}
		
		if hostHeader != "" {
			req.Host = hostHeader
			if debug {
				fmt.Printf("[DEBUG] Setting req.Host to: %s\n", hostHeader)
			}
		}

		//
		// Here we configure the HTTP client to only use HTTP/1.1 since we have found some weird bugs
		// where e.g. an Microsoft Exchange server is behind a load balancer that supports HTTP/2.0
		// but then hitting the backend Microsoft Exchange server with HTTP/2.0 causes the server
		// to return an error HTTP_1_1_REQUIRED; received from peer. I don't see an issue with using
		// only HTTP/1.1 for this tool as a way to work around this edge case.
		//

		client := retryablehttp.NewWithHTTPClient(&http.Client{
			CheckRedirect: noRedirect,

			Timeout: 5 * time.Second,

			Transport: &http.Transport{
				DialContext:  fastdialerInstance.Dial,
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
				TLSClientConfig: &tls.Config{
					Renegotiation:      tls.RenegotiateOnceAsClient,
					InsecureSkipVerify: true,
				},
			},
		}, retryablehttp.DefaultOptionsSpraying)

		resp, err := client.Do(req)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] Initial request failed for %s: %s\n", guessURL, err)
			}
			continue
		}
		
		if debug {
			fmt.Printf("[DEBUG] Initial response status for %s: %d\n", guessURL, resp.StatusCode)
		}

		// Check if NTLM is offered in the initial response
		initialAuthHeaders := resp.Header.Values("WWW-Authenticate")
		if debug {
			fmt.Printf("[DEBUG] Initial WWW-Authenticate headers for %s: %v\n", guessURL, initialAuthHeaders)
		}
		
		hasNTLM := false
		for _, header := range initialAuthHeaders {
			if strings.HasPrefix(header, "NTLM") || strings.HasPrefix(header, "Negotiate") {
				hasNTLM = true
				break
			}
		}
		
		if !hasNTLM {
			if debug {
				fmt.Printf("[DEBUG] No NTLM/Negotiate auth offered for %s\n", guessURL)
			}
			continue
		}
		
		// Now send the NTLM negotiate packet
		req2, err := retryablehttp.NewRequest("GET", guessURL, nil)
		if err != nil {
			continue
		}
		
		req2.Header.Set("Authorization", "NTLM "+MinimalNegotiatePacket)
		if hostHeader != "" {
			req2.Host = hostHeader
		}
		
		if debug {
			fmt.Printf("[DEBUG] Sending NTLM negotiate packet to %s\n", guessURL)
		}
		
		resp2, err := client.Do(req2)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] NTLM negotiate request failed for %s: %s\n", guessURL, err)
			}
			continue
		}
		
		if debug {
			fmt.Printf("[DEBUG] NTLM negotiate response status for %s: %d\n", guessURL, resp2.StatusCode)
		}

		potentialChallengeMessages := resp2.Header.Values("WWW-Authenticate")
		
		if debug {
			fmt.Printf("[DEBUG] NTLM challenge headers for %s: %v\n", guessURL, potentialChallengeMessages)
		}

		if len(potentialChallengeMessages) == 0 {
			if debug {
				fmt.Printf("[DEBUG] No WWW-Authenticate header in NTLM response for %s\n", guessURL)
			}
			continue
		}

		var splitResponse []string
		for _, potentialChallengeMessage := range potentialChallengeMessages {
			if potentialChallengeMessage == "" {
				continue
			}

			splitResponse = strings.Split(potentialChallengeMessage, " ")
			if len(splitResponse) != 2 {
				continue
			}

			if splitResponse[0] != "NTLM" {
				if debug {
					fmt.Printf("[DEBUG] Auth type is %s, not NTLM\n", splitResponse[0])
				}
				continue
			}
			
			if debug {
				fmt.Printf("[DEBUG] Found NTLM auth for %s\n", guessURL)
			}
			break
		}

		if len(splitResponse) != 2 {
			continue
		}

		base64ChallengeMessage := splitResponse[1]
		rawBytes, _ := base64.StdEncoding.DecodeString(base64ChallengeMessage)

		metadata, err := PackageMetadataFromChallengeMessage(rawBytes)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] Failed to decode NTLM challenge for %s: %s\n", guessURL, err)
			}
			continue
		}
		
		if debug {
			fmt.Printf("[DEBUG] Successfully decoded NTLM info for %s\n", guessURL)
		}

		endpoint.URL = guessURL
		endpoint.NTLMInfo = metadata

		endpoints = append(endpoints, endpoint)
	}

	if len(endpoints) == len(ntlmAppPaths) {
		endpoint := structs.NTLMReconOutput{
			URL:      url.Scheme + "://" + url.Host + "/*",
			NTLMInfo: endpoints[0].NTLMInfo,
		}

		return []structs.NTLMReconOutput{endpoint}, nil
	}

	return endpoints, nil
}

func PackageMetadataFromChallengeMessage(rawBytes []byte) (structs.NTLMInfo, error) {
	var metadata structs.NTLMInfo

	challengeMessage, err := ntlm.DecodeChallengeMessage(rawBytes)
	if err != nil {
		return metadata, err
	}

	for _, avPair := range challengeMessage.DecodedTargetInfo.AvPairs {
		switch avPair.AvId {
		case ntlm.MsvAvNbComputerName:
			metadata.ComputerName = string(ConvertUnicodeToASCII(avPair.AvData))
		case ntlm.MsvAvNbDomainName:
			metadata.DomainName = string(ConvertUnicodeToASCII(avPair.AvData))
		case ntlm.MsvAvDnsComputerName:
			metadata.DnsComputerName = string(ConvertUnicodeToASCII(avPair.AvData))
		case ntlm.MsvAvDnsDomainName:
			metadata.DnsDomainName = string(ConvertUnicodeToASCII(avPair.AvData))
		case ntlm.MsvAvDnsTreeName:
			metadata.DnsTreeName = string(ConvertUnicodeToASCII(avPair.AvData))
		}
	}

	return metadata, err
}

func ConvertUnicodeToASCII(unicodeString []byte) []byte {
	var asciiString []byte

	for i := 0; i < len(unicodeString); i += 2 {
		asciiString = append(asciiString, unicodeString[i])
	}

	return asciiString
}
