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

	knft "sigs.k8s.io/knftables"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/istio-nftables/pkg/config"
	"istio.io/istio/tools/istio-nftables/pkg/constants"
)

var IstioTableNames = []string{
	constants.IstioProxyNatTable, constants.IstioProxyMangleTable, constants.IstioProxyRawTable,
}

var IstioChainNames = []string{
	constants.IstioInboundChain, constants.IstioOutputChain, constants.IstioOutputDNSChain, constants.IstioRedirectChain,
	constants.IstioInRedirectChain, constants.IstioDivertChain, constants.IstioTproxyChain, constants.IstioPreroutingChain,
}

type NFTablesChainBuilder struct {
	Chains map[string][]knft.Chain
	cfg    *config.Config
}

type NftablesRuleBuilder struct {
	Rules map[string][]knft.Rule
	cfg   *config.Config
}

func NewNftablesChainBuilder(cfg *config.Config) *NFTablesChainBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}

	chains := make(map[string][]knft.Chain)
	for _, table := range IstioTableNames {
		chains[table] = []knft.Chain{}
	}
	return &NFTablesChainBuilder{
		Chains: chains,
		cfg:    cfg,
	}
}

func (rb *NFTablesChainBuilder) AddBaseChains(table string) *NFTablesChainBuilder {
	for _, name := range IstioTableNames {
		rb.Chains[table] = append(rb.Chains[table], knft.Chain{
			Name: name,
		})
	}
	return rb
}

func (rb *NFTablesChainBuilder) AddIstioChains(table string) *NFTablesChainBuilder {
	for _, name := range IstioChainNames {
		rb.Chains[table] = append(rb.Chains[table], knft.Chain{
			Name: name,
		})
	}
	return rb
}

func (rb *NFTablesChainBuilder) UpdateBaseChains(table string) *NFTablesChainBuilder {
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
	rules := make(map[string][]knft.Rule)
	for _, table := range IstioTableNames {
		rules[table] = []knft.Rule{}
	}
	return &NftablesRuleBuilder{
		Rules: rules,
		cfg:   cfg,
	}
}

func (rb *NftablesRuleBuilder) InsertRule(chain string, table string, position int, params ...string) *NftablesRuleBuilder {
	rules := rb.Rules[table]
	return rb.insertInternal(&rules, chain, position, params...)
}

func (rb *NftablesRuleBuilder) insertInternal(ipt *[]knft.Rule, chain string, position int, params ...string) *NftablesRuleBuilder {
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

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found.
}

func (rb *NftablesRuleBuilder) AppendRule(chain string, table string, params ...string) *NftablesRuleBuilder {
	rules := rb.Rules[table]
	return rb.appendInternal(&rules, chain, params...)
}

func (rb *NftablesRuleBuilder) appendInternal(ipt *[]knft.Rule, chain string, params ...string) *NftablesRuleBuilder {
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

// AppendVersionedRule is a wrapper around AppendRule that substitutes an ipv4/ipv6 specific value
// in place in the params. This allows appending a dual-stack rule that has an IP value in it.
func (rb *NftablesRuleBuilder) AppendVersionedRule(ipv4 string, ipv6 string, chain string, table string, params ...string) {
	rb.AppendRule(chain, table, replaceVersionSpecific(ipv4, params...)...)
	rb.AppendRule(chain, table, replaceVersionSpecific(ipv6, params...)...)
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
