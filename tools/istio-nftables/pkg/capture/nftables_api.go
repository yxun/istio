// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package capture

import (
	"context"

	"sigs.k8s.io/knftables"
)

type NftablesAPI interface {
	NewTransaction() *knftables.Transaction
	Run(ctx context.Context, tx *knftables.Transaction) error
	Dump() string
}

// RealNftables implements NftablesAPI
type RealNftables struct {
	nft knftables.Interface
}

func (r *RealNftables) Dump() string {
	// We do not use Dump in the real Interface.
	return ""
}

func NewRealNftables(family knftables.Family, table string) (*RealNftables, error) {
	nft, err := knftables.New(family, table)
	if err != nil {
		return nil, err
	}
	return &RealNftables{nft: nft}, nil
}

func (r *RealNftables) NewTransaction() *knftables.Transaction {
	return r.nft.NewTransaction()
}

func (r *RealNftables) Run(ctx context.Context, tx *knftables.Transaction) error {
	return r.nft.Run(ctx, tx)
}

// MockNftables implements NftablesAPI for testing
type MockNftables struct {
	*knftables.Fake
	DumpResults []string
}

func NewMockNftables(family knftables.Family, table string) *MockNftables {
	return &MockNftables{
		Fake:        knftables.NewFake(family, table),
		DumpResults: make([]string, 0),
	}
}

func (m *MockNftables) Dump() string {
	return m.Fake.Dump()
}
