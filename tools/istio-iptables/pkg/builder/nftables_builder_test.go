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

package builder

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	testutil "istio.io/istio/pilot/test/util"
	"istio.io/istio/tools/istio-iptables/pkg/config"
)

func compareToNftGolden(t *testing.T, name string, actual string) {
	t.Helper()
	gotBytes := []byte(actual)
	goldenFile := filepath.Join("testdata/nft", name+".golden")
	testutil.CompareContent(t, gotBytes, goldenFile)
}

func TestNftBuilder(t *testing.T) {
	cases := []struct {
		name     string
		expectV4 bool
		expectV6 bool
		config   func(builder *NftablesRuleBuilder)
	}{
		{
			"insert-single-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.InsertRuleV4("output", "filter", 8, "ip", "daddr", "127.0.0.8", "drop")
			},
		},
		{
			"insert-single-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.InsertRuleV6("output", "filter", 8, "ip", "daddr", "127.0.0.8", "drop")
			},
		},
		{
			"append-single-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
			},
		},
		{
			"append-single-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
			},
		},
		{
			"append-multi-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"append-multi-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"insert-multi-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.InsertRuleV4("output", "filter", 1, "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV4("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.InsertRuleV4("output", "filter", 3, "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"insert-multi-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.InsertRuleV6("output", "filter", 1, "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV6("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.InsertRuleV6("output", "filter", 3, "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"append-insert-multi-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV4("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"append-insert-multi-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV6("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"multi-rules-new-chain-v4",
			true,
			false,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV4("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV4("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV4("PREROUTING", "nat", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
		{
			"multi-rules-new-chain-v6",
			false,
			true,
			func(builder *NftablesRuleBuilder) {
				builder.AppendRuleV6("output", "filter", "ip", "daddr", "127.0.0.8", "drop")
				builder.InsertRuleV6("output", "filter", 2, "ip", "daddr", "127.0.0.9", "drop")
				builder.AppendRuleV6("PREROUTING", "nat", "ip", "daddr", "127.0.0.10", "drop")
			},
		},
	}
	builderConfig := &config.Config{
		EnableIPv6: true,
	}
	checkFunc := func(goldenName string, rules [][]string, expected bool) {
		// check that rules are set
		if expected {
			var actual strings.Builder
			for _, rule := range rules {
				fmt.Fprintln(&actual, strings.Join(rule, " "))
			}
			compareToNftGolden(t, goldenName, actual.String())
		}
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			nftables := NewNftablesRuleBuilder(builderConfig)
			tt.config(nftables)
			checkFunc(tt.name, nftables.BuildV4(), tt.expectV4)
			checkFunc(tt.name, nftables.BuildV6(), tt.expectV6)
		})
	}
}
