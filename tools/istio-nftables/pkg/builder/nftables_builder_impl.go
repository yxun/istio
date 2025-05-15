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

	"sigs.k8s.io/knftables"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/istio-nftables/pkg/config"
	"istio.io/istio/tools/istio-nftables/pkg/constants"
)

var IstioTableNames = []string{
	constants.IstioProxyNatTable, constants.IstioProxyMangleTable, constants.IstioProxyRawTable,
}

type NftablesRuleBuilder struct {
	Rules map[string][]knftables.Rule
	cfg   *config.Config
}

func NewNftablesRuleBuilder(cfg *config.Config) *NftablesRuleBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}
	rules := make(map[string][]knftables.Rule)
	for _, table := range IstioTableNames {
		rules[table] = []knftables.Rule{}
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

func (rb *NftablesRuleBuilder) insertInternal(ipt *[]knftables.Rule, chain string, position int, params ...string) *NftablesRuleBuilder {
	*ipt = append(*ipt, knftables.Rule{
		Chain:   chain,
		Rule:    strings.Join(params, " "),
		Index:   &position,
		Comment: knftables.PtrTo(""),
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

func (rb *NftablesRuleBuilder) appendInternal(ipt *[]knftables.Rule, chain string, params ...string) *NftablesRuleBuilder {
	idx := indexOf("jump", params)
	if idx < 0 && !strings.HasPrefix(chain, "ISTIO_") {
		log.Warnf("Appending non-jump rule in non-Istio chain (rule: %s) \n", strings.Join(params, " "))
	}
	*ipt = append(*ipt, knftables.Rule{
		Chain:   chain,
		Rule:    strings.Join(params, " "),
		Comment: knftables.PtrTo(""),
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
