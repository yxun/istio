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

package nft

import (
	"fmt"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/common/config"
	"istio.io/istio/tools/common/tproxy"
	"istio.io/istio/tools/istio-nftables/pkg/capture"
)

// We require (or rather, knftables.New does) that the nft binary be version 1.0.1
// or later, because versions before that would always attempt to parse the entire
// nft ruleset at startup, even if you were only operating on a single table.
// That's bad, because in some cases, new versions of nft have added new rule
// types in ways that triggered bugs in older versions of nft, causing them to
// crash.
func ProgramNftables(cfg *config.Config) error {
	log.Info("native nftables enabled, using nft rules for traffic redirection.")

	if !cfg.SkipRuleApply {
		nftConfigurator, err := capture.NewNftablesConfigurator(cfg)
		if err != nil {
			return err
		}

		if err := nftConfigurator.Run(); err != nil {
			return err
		}
		if err := tproxy.ConfigureRoutes(cfg); err != nil {
			return fmt.Errorf("failed to configure routes: %v", err)
		}
	}
	return nil
}
