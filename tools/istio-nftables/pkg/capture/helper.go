// Copyright Istio Authors
//
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

package capture

import (
	"strings"
)

func CombineMatchers(values []string, matcher func(value string) []string) []string {
	matchers := make([][]string, 0, len(values))
	for _, value := range values {
		matchers = append(matchers, matcher(value))
	}
	return Flatten(matchers...)
}

func Flatten(lists ...[]string) []string {
	var result []string
	for _, list := range lists {
		result = append(result, list...)
	}
	return result
}

// HasIstioLeftovers checks the given nftables state for any chains or rules related to Istio.
// It scans the provided map of tables, chains, and rules to identify any chains that start with the "ISTIO_" prefix,
// as well as any rules that involve Istio-specific jumps.
// The function returns a map where the keys are the tables, and the values are structs containing the leftover
// "ISTIO_" chains and jump rules for each table. Only tables with Istio-related leftovers are included in the result.
func HasIstioLeftovers(state map[string]map[string][]string) map[string]struct{ Chains, Rules []string } {
	output := make(map[string]struct{ Chains, Rules []string })
	for table, chains := range state {
		istioChains := []string{}
		istioJumps := []string{}
		for chain, rules := range chains {
			if strings.HasPrefix(chain, "ISTIO_") {
				istioChains = append(istioChains, chain)
			}
			for _, rule := range rules {
				if isIstioJump(rule) {
					istioJumps = append(istioJumps, rule)
				}
			}
		}
		if len(istioChains) != 0 || len(istioJumps) != 0 {
			output[table] = struct{ Chains, Rules []string }{
				Chains: istioChains,
				Rules:  istioJumps,
			}
		}
	}
	return output
}

// isIstioJump checks if the given rule is a jump to an Istio chain
func isIstioJump(rule string) bool {
	// Split the rule into fields
	fields := strings.Fields(rule)
	for i, field := range fields {
		// Check for --jump or -j in nftables commands. Check for 'jump' in nft commands.
		if field == "jump" {
			// Check if there's a next field (the target)
			if i+1 < len(fields) {
				target := strings.Trim(fields[i+1], "'\"")
				// Check if the target starts with ISTIO_
				return strings.HasPrefix(target, "ISTIO_")
			}
		}
	}
	return false
}
