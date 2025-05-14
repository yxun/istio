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
	"strings"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/istio-nftables/pkg/config"
	"istio.io/istio/tools/istio-nftables/pkg/constants"

	knft "sigs.k8s.io/knftables"
)

var ISITO_TABLE_NAMES = []string{
	constants.ISTIO_PROXY_NAT_TABLE, constants.ISTIO_PROXY_MANGLE_TABLE, constants.ISTIO_PROXY_RAW_TABLE,
}

var ISTIO_CHAIN_NAMES = []string{
	constants.ISTIO_INBOUND_CHAIN, constants.ISTIO_OUTPUT_CHAIN, constants.ISTIO_OUTPUT_DNS_CHAIN, constants.ISTIO_REDIRECT_CHAIN,
	constants.ISTIO_IN_REDIRECT_CHAIN, constants.ISTIO_DIVERT_CHAIN, constants.ISTIO_TPROXY_CHAIN, constants.ISTIO_PREROUTING_CHAIN,
}

var ISTIO_TABLE_NAMES = []string{"nat", "mangle", "raw"}

type NftablesChainBuilder struct {
	Chains map[string][]knft.Chain
	cfg    *config.Config
}

type NftablesRuleBuilder struct {
	RulesV4 map[string][]knft.Rule
	RulesV6 map[string][]knft.Rule
	cfg     *config.Config
}

func NewNftablesChainBuilder(cfg *config.Config) *NftablesChainBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}

	chains := make(map[string][]knft.Chain)
	for _, table := range ISTIO_TABLE_NAMES {
		chains[table] = []knft.Chain{}
	}
	return &NftablesChainBuilder{
		Chains: chains,
		cfg:    cfg,
	}
}

func (rb *NftablesChainBuilder) AddBaseChains(table string) *NftablesChainBuilder {
	for _, name := range ISITO_TABLE_NAMES {
		rb.Chains[table] = append(rb.Chains[table], knft.Chain{
			Name: name,
		})
	}
	return rb
}

func (rb *NftablesChainBuilder) AddIstioChains(table string) *NftablesChainBuilder {
	for _, name := range ISTIO_CHAIN_NAMES {
		rb.Chains[table] = append(rb.Chains[table], knft.Chain{
			Name: name,
		})
	}
	return rb
}

func (rb *NftablesChainBuilder) UpdateBaseChains(table string) *NftablesChainBuilder {
	for _, chain := range rb.Chains[table] {
		switch chain.Name {
		case "PREROUTING":
			*chain.Type = knft.NATType
			*chain.Hook = knft.PreroutingHook
			*chain.Priority = knft.DNATPriority
		case "INPUT":
			*chain.Type = knft.NATType
			*chain.Hook = knft.InputHook
			*chain.Priority = knft.SNATPriority
		case "OUTPUT":
			*chain.Type = knft.NATType
			*chain.Hook = knft.OutputHook
			*chain.Priority = knft.DNATPriority
		case "POSTROUTING":
			*chain.Type = knft.NATType
			*chain.Hook = knft.PostroutingHook
			*chain.Priority = knft.SNATPriority
		default:
			// Do nothing
		}
	}
	return rb
}

func NewNftablesRuleBuilder(cfg *config.Config) *NftablesRuleBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}
	rulesv4 := make(map[string][]knft.Rule)
	rulesv6 := make(map[string][]knft.Rule)
	for _, table := range ISTIO_TABLE_NAMES {
		rulesv4[table] = []knft.Rule{}
		rulesv6[table] = []knft.Rule{}
	}
	return &NftablesRuleBuilder{
		RulesV4: rulesv4,
		RulesV6: rulesv6,
		cfg:     cfg,
	}
}

func (rb *NftablesRuleBuilder) InsertRule(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	rb.InsertRuleV4(chain, table, position, params...)
	rb.InsertRuleV6(chain, table, position, params...)
	return rb
}

func (rb *NftablesRuleBuilder) insertInternal(ipt *[]knft.Rule, chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	*ipt = append(*ipt, knft.Rule{
		Chain: chain,
		Rule:  strings.Join(params, " "),
		Index: &position,
	})
	idx := indexOf("jump", params)
	if idx < 0 && !strings.HasPrefix(chain, "ISTIO_") {
		log.Warnf("Inserting non-jump rule in non-Istio chain (rule: %s) \n", strings.Join(params, " "))
	}
	return rb
}

func (rb *NftablesRuleBuilder) InsertRuleV4(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	rulesv4 := rb.RulesV4[table]
	return rb.insertInternal(&rulesv4, chain, table, position, params...)
}

func (rb *NftablesRuleBuilder) InsertRuleV6(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	if !rb.cfg.EnableIPv6 {
		return rb
	}
	rulesv6 := rb.RulesV6[table]
	return rb.insertInternal(&rulesv6, chain, table, position, params...)
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found.
}

func (rb *NftablesRuleBuilder) appendInternal(ipt *[]knft.Rule, chain string, table string, params ...string) *NftablesRuleBuilder {
	idx := indexOf("jump", params)
	if idx < 0 && !strings.HasPrefix(chain, "ISTIO_") {
		log.Warnf("Appending non-jump rule in non-Istio chain (rule: %s) \n", strings.Join(params, " "))
	}
	*ipt = append(*ipt, knft.Rule{
		Chain: chain,
		Rule:  strings.Join(params, " "),
	})
	return rb
}

func (rb *NftablesRuleBuilder) AppendRuleV4(chain string, table string, params ...string) *NftablesRuleBuilder {
	rulesv4 := rb.RulesV4[table]
	return rb.appendInternal(&rulesv4, chain, table, params...)
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
	rulesv6 := rb.RulesV6[table]
	return rb.appendInternal(&rulesv6, chain, table, params...)
}

// AppendVersionedRule is a wrapper around AppendRule that substitutes an ipv4/ipv6 specific value
// in place in the params. This allows appending a dual-stack rule that has an IP value in it.
func (rb *NftablesRuleBuilder) AppendVersionedRule(ipv4 string, ipv6 string, chain string, table string, params ...string) {
	rb.AppendRuleV4(chain, table, replaceVersionSpecific(ipv4, params...)...)
	rb.AppendRuleV6(chain, table, replaceVersionSpecific(ipv6, params...)...)
}

func replaceVersionSpecific(contents string, inputs ...string) []string {
	res := make([]string, 0, len(inputs))
	for _, i := range inputs {
		if i == constants.IPVersionSpecific {
			res = append(res, contents)
		} else {
			res = append(res, i)
		}
	}
	return res
}
