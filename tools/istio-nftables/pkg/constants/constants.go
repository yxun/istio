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

import (
	"time"

	"istio.io/istio/pkg/env"
)

const (
	// Table names used in sideCar mode when applying native nftables rules
	IstioProxyNatTable    = "ISTIO_PROXY_NAT"
	IstioProxyMangleTable = "ISTIO_PROXY_MANGLE"
	IstioProxyRawTable    = "ISTIO_PROXY_RAW"

	// Table names used in Ambient mode when applying native nftables rules
	IstioAmbientNatTable    = "ISTIO_AMBIENT_NAT"
	IstioAmbientMangleTable = "ISTIO_AMBIENT_MANGLE"
	IstioAmbientRawTable    = "ISTIO_AMBIENT_RAW"

	// Base chains.
	// TODO: Verify if we can completely avoid the following chains as base chains.
	PreroutingChain = "PREROUTING"
	OutputChain     = "OUTPUT"

	// Regular chains prefixed with "istio" to distinguish them from base chains
	IstioInboundChain    = "ISTIO_INBOUND"
	IstioOutputChain     = "ISTIO_OUTPUT"
	IstioOutputDNSChain  = "ISTIO_OUTPUT_DNS"
	IstioRedirectChain   = "ISTIO_REDIRECT"
	IstioInRedirectChain = "ISTIO_IN_REDIRECT"
	IstioDivertChain     = "ISTIO_DIVERT"
	IstioTproxyChain     = "ISTIO_TPROXY"
	IstioPreroutingChain = "ISTIO_PREROUTING"
	IstioDropChain       = "ISTIO_DROP"
)

const (
	// IPVersionSpecific is used as an input to rules that will be replaced with an ip version (v4/v6)
	// specific value
	IPVersionSpecific = "PLACEHOLDER_IP_VERSION_SPECIFIC"
)

// In TPROXY mode, mark the packet from envoy outbound to app by podIP,
// this is to prevent it being intercepted to envoy inbound listener.
const OutboundMark = "1338"

// Constants used in cobra/viper CLI
const (
	InboundInterceptionMode   = "istio-inbound-interception-mode"
	InboundTProxyMark         = "istio-inbound-tproxy-mark"
	InboundTProxyRouteTable   = "istio-inbound-tproxy-route-table"
	InboundPorts              = "istio-inbound-ports"
	LocalExcludePorts         = "istio-local-exclude-ports"
	ExcludeInterfaces         = "istio-exclude-interfaces"
	ServiceCidr               = "istio-service-cidr"
	ServiceExcludeCidr        = "istio-service-exclude-cidr"
	OutboundPorts             = "istio-outbound-ports"
	LocalOutboundPortsExclude = "istio-local-outbound-ports-exclude"
	EnvoyPort                 = "envoy-port"
	InboundCapturePort        = "inbound-capture-port"
	InboundTunnelPort         = "inbound-tunnel-port"
	ProxyUID                  = "proxy-uid"
	ProxyGID                  = "proxy-gid"
	RerouteVirtualInterfaces  = "kube-virt-interfaces"
	DryRun                    = "dry-run"
	TraceLogging              = "nftables-trace-logging"
	SkipRuleApply             = "skip-rule-apply"
	RunValidation             = "run-validation"
	NftablesProbePort         = "nftables-probe-port"
	ProbeTimeout              = "probe-timeout"
	RedirectDNS               = "redirect-dns"
	DropInvalid               = "drop-invalid"
	DualStack                 = "dual-stack"
	CaptureAllDNS             = "capture-all-dns"
	NetworkNamespace          = "network-namespace"
	CNIMode                   = "cni-mode"
	Reconcile                 = "reconcile"
	CleanupOnly               = "cleanup-only"
	ForceApply                = "force-apply"
	NativeNftables            = "native-nftables"
)

// Environment variables that deliberately have no equivalent command-line flags.
//
// The variables are defined as env.Var for documentation purposes.
//
// Use viper to resolve the value of the environment variable.
var (
	HostIPv4LoopbackCidr = env.Register("ISTIO_OUTBOUND_IPV4_LOOPBACK_CIDR", "127.0.0.1/32",
		`IPv4 CIDR range used to identify outbound traffic on loopback interface intended for application container`)

	OwnerGroupsInclude = env.Register("ISTIO_OUTBOUND_OWNER_GROUPS", "*",
		`Comma separated list of groups whose outgoing traffic is to be redirected to Envoy.
A group can be specified either by name or by a numeric GID.
The wildcard character "*" can be used to configure redirection of traffic from all groups.`)

	OwnerGroupsExclude = env.Register("ISTIO_OUTBOUND_OWNER_GROUPS_EXCLUDE", "",
		`Comma separated list of groups whose outgoing traffic is to be excluded from redirection to Envoy.
A group can be specified either by name or by a numeric GID.
Only applies when traffic from all groups (i.e. "*") is being redirected to Envoy.`)

	IstioInboundInterceptionMode = env.Register("INBOUND_INTERCEPTION_MODE", "",
		`The mode used to redirect inbound connections to Envoy, either "REDIRECT" or "TPROXY"`)

	IstioInboundTproxyMark = env.Register("INBOUND_TPROXY_MARK", "",
		``)
)

const (
	DefaultProxyUID    = "1337"
	DefaultProxyUIDInt = int64(1337)
)

// Constants used in environment variables
const (
	EnvoyUser = "ENVOY_USER"
)

// Constants for syscall
const (
	// sys/socket.h
	SoOriginalDst = 80
)

const (
	DefaultNftablesProbePortUint = 15002
	DefaultProbeTimeout          = 5 * time.Second
)

const (
	ValidationContainerName = "istio-validation"
	ValidationErrorCode     = 126
)

// DNS ports
const (
	IstioAgentDNSListenerPort = "15053"
)

// Constants for nftables CLI
const (
	NFTablesBin = "nft"
)
