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
	"io"

	"istio.io/istio/pkg/log"
)

// NftablesDependencies implementation of interface Dependencies, which is a wrapper of the knftables library
type NftablesDependencies struct {
	NetworkNamespace string
}

// Run runs a nft command using the knftables library
func (n *NftablesDependencies) Run(
	logger *log.Scope,
	quietLogging bool,
	stdin io.ReadSeeker,
	args ...string,
) (*bytes.Buffer, error) {
	return n.knftablesRun(logger, quietLogging, stdin, args...)
}

// WIP: Compare this with the iptables executeXTables method. Implement knftables calls with Istio configurations.
//
//nolint:unparam
func (n *NftablesDependencies) knftablesRun(log *log.Scope, silenceErrors bool, stdin io.ReadSeeker, args ...string,
) (*bytes.Buffer, error) {
	return nil, nil
}
