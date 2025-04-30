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
	"strings"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/tools/istio-iptables/pkg/config"
)

const (
	IPV4_TABLE_FAMILY = "ip"
	IPV6_TABLE_FAMILY = "ip6"
)

// NftablesRuleBuilder is an implementation for NftablesRuleBuilder interface
// The existing Rule structs are defined in the iptables_builder_impl.go
type NftablesRuleBuilder struct {
	rules []Rule
	cfg   *config.Config
}

// NewNftablesBuilders creates a new NftablesRuleBuilder
func NewNftablesRuleBuilder(cfg *config.Config) *NftablesRuleBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &NftablesRuleBuilder{
		rules: []Rule{},
		cfg:   cfg,
	}
}

func (rb *NftablesRuleBuilder) InsertRule(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	rb.InsertRuleV4(chain, table, position, params...)
	rb.InsertRuleV6(chain, table, position, params...)
	return rb
}

func (rb *NftablesRuleBuilder) insertInternal(ipt *[]Rule, chain string, family string, table string, position int, params ...string) *NftablesRuleBuilder {
	*ipt = append(*ipt, Rule{
		chain:  chain,
		table:  table,
		params: append([]string{"insert", "rule", family, table, chain, "position", fmt.Sprint(position)}, params...),
	})
	idx := indexOf("jump", params)
	if idx < 0 && !strings.HasPrefix(chain, "ISTIO_") {
		log.Warnf("Inserting non-jump rule in non-Istio chain (rule: %s) \n", strings.Join(params, " "))
	}
	return rb
}

func (rb *NftablesRuleBuilder) InsertRuleV4(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	return rb.insertInternal(&rb.rules, chain, IPV4_TABLE_FAMILY, table, position, params...)
}

func (rb *NftablesRuleBuilder) InsertRuleV6(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	if !rb.cfg.EnableIPv6 {
		return rb
	}
	return rb.insertInternal(&rb.rules, chain, IPV6_TABLE_FAMILY, table, position, params...)
}

func (rb *NftablesRuleBuilder) appendInternal(ipt *[]Rule, chain string, family string, table string, params ...string) *NftablesRuleBuilder {
	idx := indexOf("jump", params)
	if idx < 0 && !strings.HasPrefix(chain, "ISTIO_") {
		log.Warnf("Appending non-jump rule in non-Istio chain (rule: %s) \n", strings.Join(params, " "))
	}
	*ipt = append(*ipt, Rule{
		chain:  chain,
		table:  table,
		params: append([]string{"add", "rule", family, table, chain}, params...),
	})
	return rb
}

func (rb *NftablesRuleBuilder) AppendRuleV4(chain string, table string, params ...string) *NftablesRuleBuilder {
	return rb.appendInternal(&rb.rules, chain, IPV4_TABLE_FAMILY, table, params...)
}

func (rb *NftablesRuleBuilder) AppendRule(chain string, table string, params ...string) *NftablesRuleBuilder {
	rb.AppendRuleV4(chain, table, params...)
	rb.AppendRuleV6(chain, table, params...)
	return rb
}

func (rb *NftablesRuleBuilder) AppendRuleV6(chain string, table string, params ...string) *NftablesRuleBuilder {
	if !rb.cfg.EnableIPv6 {
		return rb
	}
	return rb.appendInternal(&rb.rules, chain, IPV6_TABLE_FAMILY, table, params...)
}

func (rb *NftablesRuleBuilder) buildRules(rules []Rule, family string) [][]string {
	output := make([][]string, 0)
	chainTableLookupSet := sets.New[string]()
	for _, r := range rules {
		chainTable := fmt.Sprintf("%s:%s", r.chain, r.table)
		// Create new chain if key: `chainTable` isn't present in map
		if !chainTableLookupSet.Contains(chainTable) {
			cmd := []string{"add", "chain", family, r.table, r.chain}
			output = append(output, cmd)
			chainTableLookupSet.Insert(chainTable)
		}
	}
	for _, r := range rules {
		output = append(output, r.params)
	}
	return output
}

func (rb *NftablesRuleBuilder) BuildV4() [][]string {
	return rb.buildRules(rb.rules, IPV4_TABLE_FAMILY)
}

func (rb *NftablesRuleBuilder) BuildV6() [][]string {
	return rb.buildRules(rb.rules, IPV6_TABLE_FAMILY)
}
