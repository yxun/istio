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

package dependencies

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"sigs.k8s.io/knftables"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
)

var testNFTRuleAdd = []string{
	"add", "rule", "ip", "filter", "INPUT", "ip", "protocol", "255", "counter",
	"drop", "comment", `"Istio no-op iptables capability probe"`,
}

// NftablesDependencies implementation of interface Dependencies, which is a wrapper of the knftables library
type NftablesDependencies struct {
	ctx              context.Context
	NetworkNamespace string
	ChainName        string
	TableFamily      knftables.Family
	TableName        string
}

// TODO: this method is in the Dependencies interface. Need to replace it with a NftablesVersion
func (n *NftablesDependencies) DetectIptablesVersion(ipv6 bool) (IptablesVersion, error) {
	return IptablesVersion{}, nil
}

// Run runs a nft command using the knftables library
func (n *NftablesDependencies) Run(
	logger *log.Scope,
	quietLogging bool,
	cmd constants.IptablesCmd,
	iptVer *IptablesVersion,
	stdin io.ReadSeeker,
	args ...string,
) (*bytes.Buffer, error) {
	return n.runNFT(logger, quietLogging, stdin, args...)
}

// WIP: Compare this with the iptables executeXTables method. Implement knftables calls with Istio configurations.
//
//nolint:unparam
func (n *NftablesDependencies) runNFT(log *log.Scope, silenceErrors bool, stdin io.ReadSeeker, args ...string,
) (*bytes.Buffer, error) {
	nft, err := knftables.New(n.TableFamily, n.TableName)
	if err != nil {
		return nil, fmt.Errorf("The system has no nftables support: %v", err)
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Chain{
		Name:    n.ChainName,
		Comment: knftables.PtrTo(""),
	})
	tx.Flush(&knftables.Chain{
		Name: n.ChainName,
	})

	tx.Add(&knftables.Rule{
		Chain: n.ChainName,
		Rule:  knftables.Concat(testNFTRuleAdd), // WIP: test testNFTRuleAdd
	})

	if err := nft.Run(n.ctx, tx); err != nil {
		return nil, nil
	}

	return nil, err
}
