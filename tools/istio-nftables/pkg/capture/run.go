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
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/knftables"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/common/config"
	"istio.io/istio/tools/istio-nftables/pkg/builder"
	"istio.io/istio/tools/istio-nftables/pkg/constants"
)

type NftablesConfigurator struct {
	cfg              *config.Config
	NetworkNamespace string
	ruleBuilder      *builder.NftablesRuleBuilder
	testRun          bool
	testResults      []string
}

type NetworkRange struct {
	IsWildcard    bool
	CIDRs         []netip.Prefix
	HasLoopBackIP bool
}

func split(s string) []string {
	return config.Split(s)
}

func NewNftablesConfigurator(cfg *config.Config) (*NftablesConfigurator, error) {
	return &NftablesConfigurator{
		cfg:              cfg,
		NetworkNamespace: cfg.NetworkNamespace,
		ruleBuilder:      builder.NewNftablesRuleBuilder(cfg),
		testRun:          false,
		testResults:      []string{},
	}, nil
}

func (cfg *NftablesConfigurator) separateV4V6(cidrList string) (NetworkRange, NetworkRange, error) {
	if cidrList == "*" {
		return NetworkRange{IsWildcard: true}, NetworkRange{IsWildcard: true}, nil
	}
	ipv6Ranges := NetworkRange{}
	ipv4Ranges := NetworkRange{}
	for _, ipRange := range split(cidrList) {
		ipp, err := netip.ParsePrefix(ipRange)
		if err != nil {
			_, err = fmt.Fprintf(os.Stderr, "Ignoring error for bug compatibility with istio-nftables: %s\n", err.Error())
			if err != nil {
				return ipv4Ranges, ipv6Ranges, err
			}
			continue
		}
		if ipp.Addr().Is4() {
			ipv4Ranges.CIDRs = append(ipv4Ranges.CIDRs, ipp)
			if ipp.Addr().IsLoopback() {
				ipv4Ranges.HasLoopBackIP = true
			}
		} else {
			ipv6Ranges.CIDRs = append(ipv6Ranges.CIDRs, ipp)
			if ipp.Addr().IsLoopback() {
				ipv6Ranges.HasLoopBackIP = true
			}
		}
	}
	return ipv4Ranges, ipv6Ranges, nil
}

func (cfg *NftablesConfigurator) logConfig() {
	// Dump out our environment for debugging purposes.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("ENVOY_PORT=%s\n", os.Getenv("ENVOY_PORT")))
	b.WriteString(fmt.Sprintf("INBOUND_CAPTURE_PORT=%s\n", os.Getenv("INBOUND_CAPTURE_PORT")))
	b.WriteString(fmt.Sprintf("ISTIO_INBOUND_INTERCEPTION_MODE=%s\n", os.Getenv("ISTIO_INBOUND_INTERCEPTION_MODE")))
	b.WriteString(fmt.Sprintf("ISTIO_INBOUND_TPROXY_ROUTE_TABLE=%s\n", os.Getenv("ISTIO_INBOUND_TPROXY_ROUTE_TABLE")))
	b.WriteString(fmt.Sprintf("ISTIO_INBOUND_PORTS=%s\n", os.Getenv("ISTIO_INBOUND_PORTS")))
	b.WriteString(fmt.Sprintf("ISTIO_OUTBOUND_PORTS=%s\n", os.Getenv("ISTIO_OUTBOUND_PORTS")))
	b.WriteString(fmt.Sprintf("ISTIO_LOCAL_EXCLUDE_PORTS=%s\n", os.Getenv("ISTIO_LOCAL_EXCLUDE_PORTS")))
	b.WriteString(fmt.Sprintf("ISTIO_EXCLUDE_INTERFACES=%s\n", os.Getenv("ISTIO_EXCLUDE_INTERFACES")))
	b.WriteString(fmt.Sprintf("ISTIO_SERVICE_CIDR=%s\n", os.Getenv("ISTIO_SERVICE_CIDR")))
	b.WriteString(fmt.Sprintf("ISTIO_SERVICE_EXCLUDE_CIDR=%s\n", os.Getenv("ISTIO_SERVICE_EXCLUDE_CIDR")))
	b.WriteString(fmt.Sprintf("ISTIO_META_DNS_CAPTURE=%s\n", os.Getenv("ISTIO_META_DNS_CAPTURE")))
	b.WriteString(fmt.Sprintf("INVALID_DROP=%s\n", os.Getenv("INVALID_DROP")))
	log.Infof("Istio nftables environment:\n%s", b.String())
	cfg.cfg.Print()
}

func (cfg *NftablesConfigurator) handleInboundPortsInclude() {
	// Handling of inbound ports. Traffic will be redirected to Envoy, which will process and forward
	// to the local service. If not set, no inbound port will be intercepted by istio nftablesOrFail.
	var table string
	if cfg.cfg.InboundPortsInclude != "" {
		if cfg.cfg.InboundInterceptionMode == "TPROXY" {
			// When using TPROXY, create a new chain for routing all inbound traffic to
			// Envoy. Any packet entering this chain gets marked with the ${INBOUND_TPROXY_MARK} mark,
			// so that they get routed to the loopback interface in order to get redirected to Envoy.
			// In the IstioInboundChain chain, 'counter jump IstioDivertChain' reroutes to the loopback
			// interface.
			// Mark all inbound packets.
			cfg.ruleBuilder.AppendRule(constants.IstioDivertChain, constants.IstioProxyMangleTable,
				"meta mark set", cfg.cfg.InboundTProxyMark)
			cfg.ruleBuilder.AppendRule(constants.IstioDivertChain, constants.IstioProxyMangleTable, "accept")

			// Create a new chain for redirecting inbound traffic to the common Envoy
			// port.
			// In the IstioInboundChain chain, 'counter RETURN' bypasses Envoy and
			// 'jump IstioTproxyChain' redirects to Envoy.
			cfg.ruleBuilder.AppendRule(constants.IstioTproxyChain, constants.IstioProxyMangleTable,
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"tproxy to", ":"+cfg.cfg.InboundCapturePort,
				"meta mark set", cfg.cfg.InboundTProxyMark+"/0xffffffff",
				"accept")
			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioTproxyChain, constants.IstioProxyMangleTable,
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"tproxy to", ":"+cfg.cfg.InboundCapturePort,
				"meta mark set", cfg.cfg.InboundTProxyMark+"/0xffffffff",
				"accept")

			table = constants.IstioProxyMangleTable
		} else {
			table = constants.IstioProxyNatTable
		}
		cfg.ruleBuilder.AppendRule(constants.PreroutingChain, table,
			"meta l4proto tcp",
			"jump", constants.IstioInboundChain)

		if cfg.cfg.InboundPortsInclude == "*" {
			// Apply any user-specified port exclusions.
			if cfg.cfg.InboundPortsExclude != "" {
				for _, port := range split(cfg.cfg.InboundPortsExclude) {
					cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, table,
						"meta l4proto tcp",
						"tcp dport", port, "return")
				}
			}
			// Redirect remaining inbound traffic to Envoy.
			if cfg.cfg.InboundInterceptionMode == "TPROXY" {
				// If an inbound packet belongs to an established socket, route it to the
				// loopback interface.
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, constants.IstioProxyMangleTable,
					"meta l4proto tcp",
					"ct state", "RELATED,ESTABLISHED",
					"jump", constants.IstioDivertChain)
				// Otherwise, it's a new connection. Redirect it using TPROXY.
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, constants.IstioProxyMangleTable,
					"meta l4proto tcp",
					"jump", constants.IstioTproxyChain)
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, constants.IstioProxyNatTable,
					"meta l4proto tcp",
					"jump", constants.IstioInRedirectChain)
			}
		} else {
			// User has specified a non-empty list of ports to be redirected to Envoy.
			for _, port := range split(cfg.cfg.InboundPortsInclude) {
				if cfg.cfg.InboundInterceptionMode == "TPROXY" {
					cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, constants.IstioProxyMangleTable,
						"meta l4proto tcp",
						"ct state", "RELATED,ESTABLISHED",
						"tcp dport", port,
						"jump", constants.IstioDivertChain)
					cfg.ruleBuilder.AppendRule(
						constants.IstioInboundChain, constants.IstioProxyMangleTable,
						"meta l4proto tcp", "tcp dport", port, "jump", constants.IstioTproxyChain)
				} else {
					cfg.ruleBuilder.AppendRule(
						constants.IstioInboundChain, constants.IstioProxyNatTable,
						"meta l4proto tcp", "tcp dport", port, "jump", constants.IstioInRedirectChain)
				}
			}
		}
	}
}

func (cfg *NftablesConfigurator) handleOutboundIncludeRules(ipv4NwRange NetworkRange, ipv6NwRange NetworkRange) {
	// Apply outbound IP inclusions.
	if ipv4NwRange.IsWildcard || ipv6NwRange.IsWildcard {
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "jump", constants.IstioRedirectChain)
		// Wildcard specified. Redirect all remaining outbound traffic to Envoy.
		for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
			cfg.ruleBuilder.InsertRule(
				constants.PreroutingChain, constants.IstioProxyNatTable, 0, "iifname", internalInterface, "jump", constants.IstioRedirectChain)
		}
	} else if len(ipv4NwRange.CIDRs) > 0 || len(ipv6NwRange.CIDRs) > 0 {
		// User has specified a non-empty list of cidrs to be redirected to Envoy.
		for _, cidr := range ipv4NwRange.CIDRs {
			for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
				cfg.ruleBuilder.InsertRule(constants.PreroutingChain, constants.IstioProxyNatTable, 0, "iifname", internalInterface,
					"ip daddr", cidr.String(), "jump", constants.IstioRedirectChain)
			}
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "ip daddr", cidr.String(), "jump", constants.IstioRedirectChain)
		}

		for _, cidr := range ipv6NwRange.CIDRs {
			for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
				cfg.ruleBuilder.InsertV6RuleIfSupported(constants.PreroutingChain, constants.IstioProxyNatTable, 0, "iifname", internalInterface,
					"ip6 daddr", cidr.String(), "jump", constants.IstioRedirectChain)
			}
			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable, "ip6 daddr",
				cidr.String(), "jump", constants.IstioRedirectChain)
		}
	}
}

func (cfg *NftablesConfigurator) shortCircuitKubeInternalInterface() {
	for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
		cfg.ruleBuilder.InsertRule(constants.PreroutingChain, constants.IstioProxyNatTable, 0, "iifname", internalInterface, "return")
	}
}

func (cfg *NftablesConfigurator) shortCircuitExcludeInterfaces() {
	for _, excludeInterface := range split(cfg.cfg.ExcludeInterfaces) {
		cfg.ruleBuilder.AppendRule(
			constants.PreroutingChain, constants.IstioProxyNatTable, "iifname", excludeInterface, "return")
		cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyNatTable, "oifname", excludeInterface, "return")
	}
	if cfg.cfg.InboundInterceptionMode == "TPROXY" {
		for _, excludeInterface := range split(cfg.cfg.ExcludeInterfaces) {

			cfg.ruleBuilder.AppendRule(
				constants.PreroutingChain, constants.IstioProxyMangleTable, "iifname", excludeInterface, "return")
			cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyMangleTable, "oifname", excludeInterface, "return")
		}
	}
}

func (cfg *NftablesConfigurator) Run() error {
	// Since OUTBOUND_IP_RANGES_EXCLUDE could carry ipv4 and ipv6 ranges
	// need to split them in different arrays one for ipv4 and one for ipv6
	// in order to not to fail
	ipv4RangesExclude, ipv6RangesExclude, err := cfg.separateV4V6(cfg.cfg.OutboundIPRangesExclude)
	if err != nil {
		return err
	}
	if ipv4RangesExclude.IsWildcard {
		return fmt.Errorf("invalid value for OUTBOUND_IP_RANGES_EXCLUDE")
	}
	// FixMe: Do we need similar check for ipv6RangesExclude as well ??

	ipv4RangesInclude, ipv6RangesInclude, err := cfg.separateV4V6(cfg.cfg.OutboundIPRangesInclude)
	if err != nil {
		return err
	}

	redirectDNS := cfg.cfg.RedirectDNS
	// How many DNS flags do we have? Three DNS flags! AH AH AH AH
	if redirectDNS && !cfg.cfg.CaptureAllDNS && len(cfg.cfg.DNSServersV4) == 0 && len(cfg.cfg.DNSServersV6) == 0 {
		log.Warn("REDIRECT_DNS is set, but CAPTURE_ALL_DNS is false, and no DNS servers provided. DNS capture disabled.")
		redirectDNS = false
	}

	cfg.logConfig()

	cfg.shortCircuitExcludeInterfaces()

	// Do not capture internal interface.
	cfg.shortCircuitKubeInternalInterface()

	// Create a rule for invalid drop in PREROUTING chain in mangle table, so the nftables will drop the out of window packets instead of reset connection .
	dropInvalid := cfg.cfg.DropInvalid
	if dropInvalid {
		cfg.ruleBuilder.AppendRule(constants.PreroutingChain, constants.IstioProxyMangleTable,
			"meta l4proto tcp",
			"ct state", "INVALID",
			"jump", constants.IstioDropChain)
		cfg.ruleBuilder.AppendRule(constants.IstioDropChain, constants.IstioProxyMangleTable, "drop")
	}

	// Create a new chain for to hit tunnel port directly. Envoy will be listening on port acting as VPN tunnel.
	cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, constants.IstioProxyNatTable,
		"meta l4proto tcp",
		"tcp dport", cfg.cfg.InboundTunnelPort,
		"return")

	// Create a new chain for redirecting outbound traffic to the common Envoy port.
	// In both chains, 'counter RETURN' bypasses Envoy and 'counter jump IstioRedirectChain'
	// redirects to Envoy.
	cfg.ruleBuilder.AppendRule(
		constants.IstioRedirectChain, constants.IstioProxyNatTable,
		"meta l4proto tcp",
		"redirect to", ":"+cfg.cfg.ProxyPort)

	// Use this chain also for redirecting inbound traffic to the common Envoy port
	// when not using TPROXY.

	cfg.ruleBuilder.AppendRule(constants.IstioInRedirectChain, constants.IstioProxyNatTable,
		"meta l4proto tcp",
		"redirect to", ":"+cfg.cfg.InboundCapturePort)

	cfg.handleInboundPortsInclude()

	// TODO: change the default behavior to not intercept any output - user may use http_proxy or another
	// nftablesOrFail wrapper (like ufw). Current default is similar with 0.1
	// Jump to the IstioOutputChain chain from OUTPUT chain for all traffic
	// NOTE: udp traffic will be optionally shunted (or no-op'd) within the IstioOutputChain chain, we don't need a conditional jump here.
	cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyNatTable, "jump", constants.IstioOutputChain)

	// Apply port based exclusions. Must be applied before connections back to self are redirected.
	if cfg.cfg.OutboundPortsExclude != "" {
		for _, port := range split(cfg.cfg.OutboundPortsExclude) {
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "tcp dport", port, "return")
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "udp dport", port, "return")
		}
	}

	// 127.0.0.6/::6 is bind connect from inbound passthrough cluster
	cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "oifname", "lo", "ip saddr", "127.0.0.6/32", "return")
	cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable, "oifname", "lo", "ip6 saddr", "::6/128", "return")

	for _, uid := range split(cfg.cfg.ProxyUID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		// nolint: lll
		if redirectDNS {
			// When DNS is enabled, we skip this for port 53. This ensures we do not have:
			// app => istio-agent => Envoy inbound => dns server
			// Instead, we just have:
			// app => istio-agent => dns server

			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"tcp dport", "!=", "{ "+"53, "+cfg.cfg.InboundTunnelPort+" }",
				"skuid", uid,
				"jump", constants.IstioInRedirectChain)

			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"tcp dport", "!=", "{ "+"53, "+cfg.cfg.InboundTunnelPort+" }",
				"skuid", uid,
				"jump", constants.IstioInRedirectChain)

		} else {
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
				"skuid", uid,
				"jump", constants.IstioInRedirectChain)

			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
				"skuid", uid,
				"jump", constants.IstioInRedirectChain)
		}
		// Do not redirect app calls to back itself via Envoy when using the endpoint address
		// e.g. appN => appN by lo
		// If loopback explicitly set via OutboundIPRangesInclude, then don't return.
		if !ipv4RangesInclude.HasLoopBackIP && !ipv6RangesInclude.HasLoopBackIP {
			if redirectDNS {
				// Users may have a DNS server that is on localhost. In these cases, applications may
				// send TCP traffic to the DNS server that we actually *do* want to intercept. To
				// handle this case, we exclude port 53 from this rule. Note: We cannot just move the
				// port 53 redirection rule further up the list, as we will want to avoid capturing
				// DNS requests from the proxy UID/GID
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
					"oifname", "lo",
					"meta l4proto tcp",
					"tcp dport", "!=", "53",
					"skuid", uid,
					"return")
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
					"oifname", "lo",
					"skuid", "!=", uid,
					"return")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"skuid", uid,
			"return")
	}

	for _, gid := range split(cfg.cfg.ProxyGID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"oifname", "lo",
			"meta l4proto tcp",
			"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
			"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
			"skgid", gid,
			"jump", constants.IstioInRedirectChain)

		cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"oifname", "lo",
			"meta l4proto tcp",
			"ip6 daddr", "!=", "::1/128",
			"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
			"skgid", gid,
			"jump", constants.IstioInRedirectChain)

		// Do not redirect app calls to back itself via Envoy when using the endpoint address
		// e.g. appN => appN by lo
		// If loopback explicitly set via OutboundIPRangesInclude, then don't return.
		if !ipv4RangesInclude.HasLoopBackIP && !ipv6RangesInclude.HasLoopBackIP {
			if redirectDNS {
				// Users may have a DNS server that is on localhost. In these cases, applications may
				// send TCP traffic to the DNS server that we actually *do* want to intercept. To
				// handle this case, we exclude port 53 from this rule. Note: We cannot just move the
				// port 53 redirection rule further up the list, as we will want to avoid capturing
				// DNS requests from the proxy UID/GID
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
					"oifname", "lo",
					"meta l4proto tcp",
					"tcp dport", "!=", "53",
					"skgid", "!=", gid,
					"return")
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
					"oifname", "lo",
					"skgid", "!=", gid,
					"return")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"skgid", gid,
			"return")
	}

	ownerGroupsFilter := config.ParseInterceptFilter(cfg.cfg.OwnerGroupsInclude, cfg.cfg.OwnerGroupsExclude)

	cfg.handleCaptureByOwnerGroup(ownerGroupsFilter)

	if redirectDNS {
		cfg.SetupDNSRedir(
			cfg.ruleBuilder, cfg.cfg.ProxyUID, cfg.cfg.ProxyGID,
			cfg.cfg.DNSServersV4, cfg.cfg.DNSServersV6, cfg.cfg.CaptureAllDNS,
			ownerGroupsFilter)
	}

	// Skip redirection for Envoy-aware applications and
	// container-to-container traffic both of which explicitly use
	// localhost.
	cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
		"ip daddr", cfg.cfg.HostIPv4LoopbackCidr, "return")

	cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable,
		"ip6 daddr", "::1/128", "return")

	// Apply outbound IPv4 exclusions. Must be applied before inclusions.
	for _, cidr := range ipv4RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"ip daddr", cidr.String(),
			"return")
	}
	for _, cidr := range ipv6RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendV6RuleIfSupported(constants.IstioOutputChain, constants.IstioProxyNatTable,
			"ip6 daddr", cidr.String(),
			"return")
	}

	cfg.handleOutboundPortsInclude()

	cfg.handleOutboundIncludeRules(ipv4RangesInclude, ipv6RangesInclude)

	if cfg.cfg.InboundInterceptionMode == "TPROXY" {
		// save packet mark set by envoy.filters.listener.original_src as connection mark
		cfg.ruleBuilder.AppendRule(constants.PreroutingChain, constants.IstioProxyMangleTable,
			"meta l4proto tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"CT mark set mark")
		// If the packet is already marked with 1337, then return. This is to prevent mark envoy --> app traffic again.
		cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyMangleTable,
			"oifname", "lo",
			"meta l4proto tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"return")
		for _, uid := range split(cfg.cfg.ProxyUID) {
			// mark outgoing packets from envoy to workload by pod ip
			// app call VIP --> envoy outbound -(mark 1338)-> envoy inbound --> app
			cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyMangleTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"skuid", uid,
				"meta mark set", constants.OutboundMark)
			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.OutputChain, constants.IstioProxyMangleTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"skuid", uid,
				"meta mark set", constants.OutboundMark)
		}
		for _, gid := range split(cfg.cfg.ProxyGID) {
			// mark outgoing packets from envoy to workload by pod ip
			// app call VIP --> envoy outbound -(mark 1338)-> envoy inbound --> app
			cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyMangleTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"skgid", gid,
				"meta mark set", constants.OutboundMark)
			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.OutputChain, constants.IstioProxyMangleTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"skgid", gid,
				"meta mark set", constants.OutboundMark)
		}
		// mark outgoing packets from workload, match it to policy routing entry setup for TPROXY mode
		cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.IstioProxyMangleTable,
			"meta l4proto tcp",
			"CT", "mark", cfg.cfg.InboundTProxyMark,
			"meta mark set", "CT", "mark")
		// prevent infinite redirect
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, constants.IstioProxyMangleTable, 0,
			"meta l4proto tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"return")
		// prevent intercept traffic from envoy/pilot-agent ==> app by 127.0.0.6 --> podip
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, constants.IstioProxyMangleTable, 1,
			"iifname", "lo",
			"meta l4proto tcp",
			"ip saddr", "127.0.0.6/32",
			"return")
		cfg.ruleBuilder.InsertV6RuleIfSupported(constants.IstioInboundChain, constants.IstioProxyMangleTable, 1,
			"iifname", "lo",
			"meta l4proto tcp",
			"ip6 saddr", "::6/128",
			"return")
		// prevent intercept traffic from app ==> app by pod ip
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, constants.IstioProxyMangleTable, 2,
			"iifname", "lo",
			"meta l4proto tcp",
			"mark", "!=", constants.OutboundMark,
			"return")
	}

	return cfg.executeCommands()
}

// SetupDNSRedir is a helper function to tackle with DNS UDP specific operations.
// This helps the creation logic of DNS UDP rules in sync with the deletion.
func (cfg *NftablesConfigurator) SetupDNSRedir(nft *builder.NftablesRuleBuilder, proxyUID, proxyGID string,
	dnsServersV4 []string, dnsServersV6 []string, captureAllDNS bool, ownerGroupsFilter config.InterceptFilter,
) {
	// Uniquely for DNS (at this time) we need a jump in "raw:OUTPUT", so this jump is conditional on that setting.
	// And, unlike nat/OUTPUT, we have no shared rules, so no need to do a 2-level jump at this time
	nft.AppendRule(constants.OutputChain, constants.IstioProxyRawTable, "jump", constants.IstioOutputDNSChain)

	// Conditionally insert jumps for V6 and V4 - we may have DNS capture enabled for V4 servers but not V6, or vice versa.
	// This avoids creating no-op jumps in v6 if we only need them in v4.
	//
	// TODO we should probably *conditionally* create jumps if and only if rules exist in the jumped-to table,
	// in a more automatic fashion.
	if captureAllDNS || len(dnsServersV4) > 0 {
		nft.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "jump", constants.IstioOutputDNSChain)
	}

	if captureAllDNS || len(dnsServersV6) > 0 {
		nft.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable, "jump", constants.IstioOutputDNSChain)
	}

	if captureAllDNS {
		// Redirect all TCP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(
			constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
			"meta l4proto tcp",
			"tcp dport", "53",
			"redirect",
			"to", ":"+constants.IstioAgentDNSListenerPort)
	} else {
		for _, s := range dnsServersV4 {
			// redirect all TCP dns traffic on port 53 to the agent on port 15053 for all servers
			// in etc/resolv.conf
			// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
			// such as: app -> istio dns server -> dnsmasq -> upstream
			// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
			// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
			// pointed to server X, this would not work. However, the assumption is that is not a common case.
			nft.AppendRule(
				constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
				"ip daddr", s+"/32",
				"tcp dport", "53",
				"redirect",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendV6RuleIfSupported(
				constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
				"ip6 daddr", s+"/128",
				"tcp dport", "53",
				"redirect",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
	}

	if captureAllDNS {
		// Redirect all UDP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
			"udp dport", "53",
			"redirect",
			"to", ":"+constants.IstioAgentDNSListenerPort)
	} else {
		// redirect all UDP dns traffic on port 53 to the agent on port 15053 for all servers
		// in etc/resolv.conf
		// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
		// such as: app -> istio dns server -> dnsmasq -> upstream
		// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
		// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
		// pointed to server X, this would not work. However, the assumption is that is not a common case.
		for _, s := range dnsServersV4 {
			nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
				"ip daddr", s+"/32",
				"udp dport", "53",
				"redirect",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendV6RuleIfSupported(constants.IstioOutputDNSChain, constants.IstioProxyNatTable,
				"ip6 daddr", s+"/128",
				"udp dport", "53",
				"redirect",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
	}
	// Split UDP DNS traffic to separate conntrack zones
	cfg.addDNSConntrackZones(nft, proxyUID, proxyGID, dnsServersV4, dnsServersV6, captureAllDNS)
}

// addDNSConntrackZones is a helper function to add nftables rules to split DNS traffic
// in two separate conntrack zones to avoid issues with UDP conntrack race conditions.
// Traffic that goes from istio to DNS servers and vice versa are zone 1 and traffic from
// DNS client to istio and vice versa goes to zone 2
func (cfg *NftablesConfigurator) addDNSConntrackZones(
	nft *builder.NftablesRuleBuilder, proxyUID, proxyGID string, dnsServersV4 []string, dnsServersV6 []string, captureAllDNS bool,
) {
	for _, uid := range split(proxyUID) {
		// Packets with dst port 53 from istio to zone 1. These are Istio calls to upstream resolvers
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
			"udp dport", "53",
			"meta",
			"skuid", uid,
			"CT", "zone", "set", "1")
		// Packets with src port 15053 from istio to zone 2. These are Istio response packets to application clients
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
			"udp sport", "15053",
			"meta",
			"skuid", uid,
			"CT", "zone", "set", "2")
	}
	for _, gid := range split(proxyGID) {
		// Packets with dst port 53 from istio to zone 1. These are Istio calls to upstream resolvers
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
			"udp dport", "53",
			"meta",
			"skgid", gid,
			"CT", "zone", "set", "1")
		// Packets with src port 15053 from istio to zone 2. These are Istio response packets to application clients
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
			"udp sport", "15053",
			"meta",
			"skgid", gid,
			"CT", "zone", "set", "2")
	}

	// For DNS conntrack, we need (at least one) inbound rule in raw/PREROUTING, so make a chain
	// and jump to it. NOTE that we are conditionally creating the jump from the nat/PREROUTING chain
	// to the ISTIO_INBOUND chain here, because otherwise it is possible to create a jump to an empty chain,
	// which the reconciliation logic currently ignores/won't clean up.
	//
	// TODO in practice this is harmless - a jump to an empty chain is a no-op - but it borks tests.
	if captureAllDNS {
		nft.AppendRule(constants.PreroutingChain, constants.IstioProxyRawTable, "jump", constants.IstioInboundChain)
		// Not specifying destination address is useful for the CNI case where pod DNS server address cannot be decided.

		// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
		nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
			"udp dport", "53",
			"CT", "zone", "set", "2")
		// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
		nft.AppendRule(constants.IstioInboundChain, constants.IstioProxyRawTable,
			"udp sport", "53",
			"CT", "zone", "set", "1")
	} else {

		if len(dnsServersV4) != 0 || len(dnsServersV6) != 0 {
			nft.AppendRule(constants.PreroutingChain, constants.IstioProxyRawTable, "jump", constants.IstioInboundChain)
		}
		// Go through all DNS servers in etc/resolv.conf and mark the packets based on these destination addresses.
		for _, s := range dnsServersV4 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendRule(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
				"udp dport", "53",
				"ip daddr", s+"/32",
				"CT", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendRule(constants.IstioInboundChain, constants.IstioProxyRawTable,
				"udp sport", "53",
				"ip daddr", s+"/32",
				"CT", "zone", "set", "1")
		}

		for _, s := range dnsServersV6 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendV6RuleIfSupported(constants.IstioOutputDNSChain, constants.IstioProxyRawTable,
				"udp dport", "53",
				"ip6 daddr", s+"/128",
				"CT", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendV6RuleIfSupported(constants.IstioInboundChain, constants.IstioProxyRawTable,
				"udp sport", "53",
				"ip6 daddr", s+"/128",
				"CT", "zone", "set", "1")
		}
	}
}

func (cfg *NftablesConfigurator) handleOutboundPortsInclude() {
	if cfg.cfg.OutboundPortsInclude != "" {
		for _, port := range split(cfg.cfg.OutboundPortsInclude) {
			cfg.ruleBuilder.AppendRule(
				constants.IstioOutputChain, constants.IstioProxyNatTable, "tcp dport", port, "jump", constants.IstioRedirectChain)
		}
	}
}

func (cfg *NftablesConfigurator) handleCaptureByOwnerGroup(filter config.InterceptFilter) {
	if filter.Except {
		for _, group := range filter.Values {
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
				"skgid", group,
				"return")
		}
	} else {
		groupIsNoneOf := CombineMatchers(filter.Values, func(group string) []string {
			return []string{"skgid", "!=", group}
		})
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, constants.IstioProxyNatTable,
			append(groupIsNoneOf, "return")...)
	}
}

func (cfg *NftablesConfigurator) addIstioNatTableRules(nft knftables.Interface) error {
	tx := nft.NewTransaction()
	// Ensure that our table exists.
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo(""),
	})

	// Ensure that our chains exist
	tx.Add(&knftables.Chain{
		Name:     constants.PreroutingChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})
	tx.Add(&knftables.Chain{
		Name:     constants.OutputChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioInboundChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioRedirectChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioInRedirectChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioOutputChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioOutputDNSChain,
		Comment: knftables.PtrTo(""),
	})

	// we use chainRuleCount to keep track of how many rules have been added to each chain.
	chainRuleCount := make(map[string]int)

	for _, rule := range cfg.ruleBuilder.Rules[constants.IstioProxyNatTable] {
		chain := rule.Chain

		// In IPtables, inserting a rule at position 1 means it gets placed at the head of the chain. In contrast,
		// nftables starts rule indexing at 0. However, nftables doesn't allow inserting a rule at index 0 if the
		// chain is empty. So to handle this case, we check if the chain is empty, and if it is, we use appendRule instead.
		if rule.Index != nil && chainRuleCount[chain] == 0 {
			rule.Index = nil
		}

		// When a rule includes the Index, its considered as an Insert request.
		if rule.Index != nil {
			tx.Insert(&rule)
		} else {
			tx.Add(&rule)
		}
		chainRuleCount[chain]++
	}

	// Apply changes in this transaction
	return nft.Run(context.TODO(), tx)
}

func (cfg *NftablesConfigurator) addIstioMangleTableRules(nft knftables.Interface) error {
	// If there are no rules to be added to the IstioProxyMangleTable, skip creating the associated tables and chains.
	if len(cfg.ruleBuilder.Rules[constants.IstioProxyMangleTable]) == 0 {
		return nil
	}

	tx := nft.NewTransaction()
	// Ensure that our table exists.
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo(""),
	})

	// Ensure that our chains exist
	tx.Add(&knftables.Chain{
		Name:     constants.PreroutingChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.ManglePriority),
	})
	tx.Add(&knftables.Chain{
		Name:     constants.OutputChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.ManglePriority),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioDivertChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioTproxyChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioInboundChain,
		Comment: knftables.PtrTo(""),
	})

	// Add Mangle table rules
	for _, rule := range cfg.ruleBuilder.Rules[constants.IstioProxyMangleTable] {
		tx.Add(&rule)
	}

	// Apply changes in this transaction
	return nft.Run(context.TODO(), tx)
}

func (cfg *NftablesConfigurator) addIstioRawTableRules(nft knftables.Interface) error {
	// If there are no rules to be added to the IstioProxyRawTable, skip creating the associated tables and chains.
	if len(cfg.ruleBuilder.Rules[constants.IstioProxyRawTable]) == 0 {
		return nil
	}

	tx := nft.NewTransaction()
	// Ensure that our table exists.
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo(""),
	})

	// Ensure that our chains exist
	tx.Add(&knftables.Chain{
		Name:     constants.PreroutingChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.RawPriority),
	})
	tx.Add(&knftables.Chain{
		Name:     constants.OutputChain,
		Comment:  knftables.PtrTo(""),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.RawPriority),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioInboundChain,
		Comment: knftables.PtrTo(""),
	})
	tx.Add(&knftables.Chain{
		Name:    constants.IstioOutputDNSChain,
		Comment: knftables.PtrTo(""),
	})

	// Add RAW table rules
	for _, rule := range cfg.ruleBuilder.Rules[constants.IstioProxyRawTable] {
		tx.Add(&rule)
	}

	// Apply changes in this transaction
	return nft.Run(context.TODO(), tx)
}

// executeCommands creates a knftables.Interface and apply all changes to the target system if it is not a test run.
// If the cfg.testRun is true, it creates a knftables.Fake interface and it will not apply rules to the target system.
func (cfg *NftablesConfigurator) executeCommands() error {
	var nft knftables.Interface
	if !cfg.testRun {
		nft, err := knftables.New(knftables.InetFamily, constants.IstioProxyNatTable)
		if err != nil {
			return err
		}
		if err := cfg.addIstioNatTableRules(nft); err != nil {
			return err
		}
		nft, err = knftables.New(knftables.InetFamily, constants.IstioProxyMangleTable)
		if err != nil {
			return err
		}
		if err := cfg.addIstioMangleTableRules(nft); err != nil {
			return err
		}
		nft, err = knftables.New(knftables.InetFamily, constants.IstioProxyRawTable)
		if err != nil {
			return err
		}
		if err := cfg.addIstioRawTableRules(nft); err != nil {
			return err
		}
	} else {
		// testRun is true, this mode is running for testing.
		nft = knftables.NewFake(knftables.InetFamily, constants.IstioProxyNatTable)
		if err := cfg.addIstioNatTableRules(nft); err != nil {
			return err
		}
		if err := cfg.buildTestResults(nft, constants.IstioProxyNatTable); err != nil {
			return err
		}
		nft = knftables.NewFake(knftables.InetFamily, constants.IstioProxyMangleTable)
		if err := cfg.addIstioMangleTableRules(nft); err != nil {
			return err
		}
		if err := cfg.buildTestResults(nft, constants.IstioProxyMangleTable); err != nil {
			return err
		}
		nft = knftables.NewFake(knftables.InetFamily, constants.IstioProxyRawTable)
		if err := cfg.addIstioRawTableRules(nft); err != nil {
			return err
		}
		if err := cfg.buildTestResults(nft, constants.IstioProxyRawTable); err != nil {
			return err
		}
	}
	return nil
}

func (cfg *NftablesConfigurator) buildTestResults(nft knftables.Interface, table string) error {
	if len(cfg.ruleBuilder.Rules[table]) != 0 {
		cfg.testResults = append(cfg.testResults, "# Table: "+table)
		chains, err := nft.List(context.TODO(), "chain")
		if err != nil {
			return err
		}
		// FIXME: the nft.List does not return items in order.
		// So need to sort the results for idempotent testing.
		sort.Strings(chains)
		for _, chain := range chains {
			cfg.testResults = append(cfg.testResults, "# Chain: "+chain)
			rules, err := nft.ListRules(context.TODO(), chain)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				cfg.testResults = append(cfg.testResults, rule.Rule)
			}
		}
	}
	return nil
}

func CombineMatchers(values []string, matcher func(value string) []string) []string {
	matchers := make([][]string, 0, len(values))
	for _, value := range values {
		matchers = append(matchers, matcher(value))
	}
	return Flatten(matchers...)
}

func Flatten(lists ...[]string) []string {
	var result []string
	for _, list := range lists {
		result = append(result, list...)
	}
	return result
}
