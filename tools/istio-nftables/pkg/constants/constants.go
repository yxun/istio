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

package constants

const (
	// Table names used in sideCar mode when applying native nftables rules
	IstioProxyNatTable    = "istio-proxy-nat"
	IstioProxyMangleTable = "istio-proxy-mangle"
	IstioProxyRawTable    = "istio-proxy-raw"

	// Table names used in Ambient mode when applying native nftables rules
	IstioAmbientNatTable    = "istio-ambient-nat"
	IstioAmbientMangleTable = "istio-ambient-mangle"
	IstioAmbientRawTable    = "istio-ambient-raw"

	// Base chains.
	PreroutingChain = "prerouting"
	OutputChain     = "output"

	// Regular chains prefixed with "istio" to distinguish them from base chains
	IstioInboundChain    = "istio-inbound"
	IstioOutputChain     = "istio-output"
	IstioOutputDNSChain  = "istio-output-dns"
	IstioRedirectChain   = "istio-redirect"
	IstioInRedirectChain = "istio-in-redirect"
	IstioDivertChain     = "istio-divert"
	IstioTproxyChain     = "istio-tproxy"
	IstioPreroutingChain = "istio-prerouting"
	IstioDropChain       = "ISTIO_DROP"
)

// In TPROXY mode, mark the packet from envoy outbound to app by podIP,
// this is to prevent it being intercepted to envoy inbound listener.
const OutboundMark = "1338"

// DNS ports
const (
	IstioAgentDNSListenerPort = "15053"
)
