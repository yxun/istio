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
	"strings"

	"sigs.k8s.io/knftables"

	"istio.io/istio/pkg/log"
	"istio.io/istio/tools/istio-nftables/pkg/builder"
	"istio.io/istio/tools/istio-nftables/pkg/config"
	"istio.io/istio/tools/istio-nftables/pkg/constants"
)

type NftablesConfigurator struct {
	cfg              *config.Config
	NetworkNamespace string
	chainBuilder     *builder.NFTablesChainBuilder
	ruleBuilder      *builder.NftablesRuleBuilder
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
		chainBuilder:     builder.NewNftablesChainBuilder(cfg),
		ruleBuilder:      builder.NewNftablesRuleBuilder(cfg),
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
			cfg.ruleBuilder.AppendRule(constants.IstioDivertChain, "mangle",
				"counter meta mark set", cfg.cfg.InboundTProxyMark)
			cfg.ruleBuilder.AppendRule(constants.IstioDivertChain, "mangle", "counter accept")

			// Create a new chain for redirecting inbound traffic to the common Envoy
			// port.
			// In the IstioInboundChain chain, 'counter RETURN' bypasses Envoy and
			// 'jump IstioTproxyChain' redirects to Envoy.
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128",
				constants.IstioTproxyChain, "mangle",
				"ip protocol", "tcp",
				"ip daddr", "!=", constants.IPVersionSpecific,
				"tproxy to", cfg.cfg.InboundCapturePort,
				"meta mark set", cfg.cfg.InboundTProxyMark+"/0xffffffff",
				"accept")
			table = "mangle"
		} else {
			table = "nat"
		}
		cfg.ruleBuilder.AppendRule("PREROUTING", table,
			"ip protocol", "tcp",
			"counter", "jump", constants.IstioInboundChain)

		if cfg.cfg.InboundPortsInclude == "*" {
			// Apply any user-specified port exclusions.
			if cfg.cfg.InboundPortsExclude != "" {
				for _, port := range split(cfg.cfg.InboundPortsExclude) {
					cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, table,
						"tcp dport", port,
						"counter", "RETURN")
				}
			}
			// Redirect remaining inbound traffic to Envoy.
			if cfg.cfg.InboundInterceptionMode == "TPROXY" {
				// If an inbound packet belongs to an established socket, route it to the
				// loopback interface.
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, "mangle",
					"ip protocol", "tcp",
					"ct state", "RELATED,ESTABLISHED",
					"counter", "jump", constants.IstioDivertChain)
				// Otherwise, it's a new connection. Redirect it using TPROXY.
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, "mangle",
					"ip protocol", "tcp",
					"counter", "jump", constants.IstioTproxyChain)
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, "nat",
					"ip protocol", "tcp",
					"counter", "jump", constants.IstioInRedirectChain)
			}
		} else {
			// User has specified a non-empty list of ports to be redirected to Envoy.
			for _, port := range split(cfg.cfg.InboundPortsInclude) {
				if cfg.cfg.InboundInterceptionMode == "TPROXY" {
					cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, "mangle",
						"ip protocol", "tcp",
						"ct state", "RELATED,ESTABLISHED",
						"tcp dport", port,
						"counter", "jump", constants.IstioDivertChain)
					cfg.ruleBuilder.AppendRule(
						constants.IstioInboundChain, "mangle", "tcp dport", port, "counter", "jump", constants.IstioTproxyChain)
				} else {
					cfg.ruleBuilder.AppendRule(
						constants.IstioInboundChain, "nat", "tco dport", port, "counter", "jump", constants.IstioInRedirectChain)
				}
			}
		}
	}
}

func (cfg *NftablesConfigurator) handleOutboundIncludeRules(
	rangeInclude NetworkRange,
	appendRule func(chain string, table string, params ...string) *builder.NftablesRuleBuilder,
	insert func(chain string, table string, position int, params ...string) *builder.NftablesRuleBuilder,
) {
	// Apply outbound IP inclusions.
	if rangeInclude.IsWildcard {
		// Wildcard specified. Redirect all remaining outbound traffic to Envoy.
		appendRule(constants.IstioOutputChain, "nat", "counter", "jump", constants.IstioRedirectChain)
		for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
			insert(
				"PREROUTING", "nat", 1, "iifname", internalInterface, "counter", "jump", constants.IstioRedirectChain)
		}
	} else if len(rangeInclude.CIDRs) > 0 {
		// User has specified a non-empty list of cidrs to be redirected to Envoy.
		for _, cidr := range rangeInclude.CIDRs {
			for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
				insert("PREROUTING", "nat", 1, "iifname", internalInterface,
					"ip daddr", cidr.String(), "counter", "jump", constants.IstioRedirectChain)
			}
			appendRule(
				constants.IstioOutputChain, "nat", "ip daddr", cidr.String(), "counter", "jump", constants.IstioRedirectChain)
		}
	}
}

func (cfg *NftablesConfigurator) shortCircuitKubeInternalInterface() {
	for _, internalInterface := range split(cfg.cfg.RerouteVirtualInterfaces) {
		cfg.ruleBuilder.InsertRule("PREROUTING", "nat", 1, "iifname", internalInterface, "counter", "RETURN")
	}
}

func (cfg *NftablesConfigurator) shortCircuitExcludeInterfaces() {
	for _, excludeInterface := range split(cfg.cfg.ExcludeInterfaces) {
		cfg.ruleBuilder.AppendRule(
			"PREROUTING", "nat", "iifname", excludeInterface, "counter", "RETURN")
		cfg.ruleBuilder.AppendRule("OUTPUT", "nat", "oifname", excludeInterface, "counter", "RETURN")
	}
	if cfg.cfg.InboundInterceptionMode == "TPROXY" {
		for _, excludeInterface := range split(cfg.cfg.ExcludeInterfaces) {

			cfg.ruleBuilder.AppendRule(
				"PREROUTING", "iifname", excludeInterface, "counter", "RETURN")
			cfg.ruleBuilder.AppendRule("OUTPUT", "oifname", excludeInterface, "counter", "RETURN")
		}
	}
}

func ignoreExists(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "file exists") {
		return nil
	}
	return err
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
		cfg.ruleBuilder.AppendRule("PREROUTING", "mangle",
			"ip protocol", "tcp",
			"ct state", "INVALID",
			"counter", "jump", constants.IstioDropChain)
		cfg.ruleBuilder.AppendRule(constants.IstioDropChain, "mangle", "counter", "DROP")
	}

	// Create a new chain for to hit tunnel port directly. Envoy will be listening on port acting as VPN tunnel.
	cfg.ruleBuilder.AppendRule(constants.IstioInboundChain, "nat",
		"tcp dport", cfg.cfg.InboundTunnelPort,
		"counter", "RETURN")

	// Create a new chain for redirecting outbound traffic to the common Envoy port.
	// In both chains, 'counter RETURN' bypasses Envoy and 'counter jump IstioRedirectChain'
	// redirects to Envoy.
	cfg.ruleBuilder.AppendRule(
		constants.IstioRedirectChain, "nat",
		"ip protocol", "tcp",
		"counter", "redirect to", cfg.cfg.ProxyPort)

	// Use this chain also for redirecting inbound traffic to the common Envoy port
	// when not using TPROXY.

	cfg.ruleBuilder.AppendRule(constants.IstioInRedirectChain, "nat",
		"ip protocol", "tcp",
		"counter", "redirect to", cfg.cfg.InboundCapturePort)

	cfg.handleInboundPortsInclude()

	// TODO: change the default behavior to not intercept any output - user may use http_proxy or another
	// nftablesOrFail wrapper (like ufw). Current default is similar with 0.1
	// Jump to the IstioOutputChain chain from OUTPUT chain for all traffic
	// NOTE: udp traffic will be optionally shunted (or no-op'd) within the IstioOutputChain chain, we don't need a conditional jump here.
	cfg.ruleBuilder.AppendRule("OUTPUT", "nat", "counter", "jump", constants.IstioOutputChain)

	// Apply port based exclusions. Must be applied before connections back to self are redirected.
	if cfg.cfg.OutboundPortsExclude != "" {
		for _, port := range split(cfg.cfg.OutboundPortsExclude) {
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat", "tcp dport", port, "counter", "RETURN")
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat", "udp dport", port, "counter", "RETURN")
		}
	}

	// 127.0.0.6/::6 is bind connect from inbound passthrough cluster
	cfg.ruleBuilder.AppendVersionedRule("127.0.0.6/32", "::6/128", constants.IstioOutputChain, "nat",
		"oifname", "lo", "ip saddr", constants.IPVersionSpecific, "counter", "RETURN")

	for _, uid := range split(cfg.cfg.ProxyUID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		// nolint: lll
		if redirectDNS {
			// When DNS is enabled, we skip this for port 53. This ensures we do not have:
			// app => istio-agent => Envoy inbound => dns server
			// Instead, we just have:
			// app => istio-agent => dns server
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.IstioOutputChain, "nat",
				"oifname", "lo",
				"ip protocol", "tcp",
				"ip daddr", "!=", constants.IPVersionSpecific,
				"tcp dport", "!={", "53, "+cfg.cfg.InboundTunnelPort, "}",
				"skuid", uid,
				"counter", "jump", constants.IstioInRedirectChain)
		} else {
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.IstioOutputChain, "nat",
				"oifname", "lo",
				"ip protocol", "tcp",
				"ip daddr", "!=", constants.IPVersionSpecific,
				"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
				"skuid", uid,
				"counter", "jump", constants.IstioInRedirectChain)
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
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
					"oifname", "lo",
					"ip protocol", "tcp",
					"tcp dport", "!=", "53",
					"skuid", uid,
					"counter", "RETURN")
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
					"oifname", "lo",
					"skuid", "!=", uid,
					"counter", "RETURN")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
			"skuid", uid,
			"counter", "RETURN")
	}

	for _, gid := range split(cfg.cfg.ProxyGID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.IstioOutputChain, "nat",
			"oifname", "lo",
			"ip protocol", "tcp",
			"ip daddr", "!=", constants.IPVersionSpecific,
			"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
			"skgid", gid,
			"counter", "jump", constants.IstioInRedirectChain)

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
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
					"oifname", "lo",
					"ip protocol", "tcp",
					"tcp dport", "!=", "53",
					"skgid", "!=", gid,
					"counter", "RETURN")
			} else {
				cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
					"oifname", "lo",
					"skgid", "!=", gid,
					"counter", "RETURN")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
			"skgid", gid,
			"counter", "RETURN")
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
	cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.IstioOutputChain, "nat",
		"ip daddr", constants.IPVersionSpecific,
		"counter", "RETURN")
	// Apply outbound IPv4 exclusions. Must be applied before inclusions.
	for _, cidr := range ipv4RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
			"ip daddr", cidr.String(),
			"counter", "RETURN")
	}
	for _, cidr := range ipv6RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
			"ip daddr", cidr.String(),
			"counter", "RETURN")
	}

	cfg.handleOutboundPortsInclude()

	cfg.handleOutboundIncludeRules(ipv4RangesInclude, cfg.ruleBuilder.AppendRule, cfg.ruleBuilder.InsertRule)
	cfg.handleOutboundIncludeRules(ipv6RangesInclude, cfg.ruleBuilder.AppendRule, cfg.ruleBuilder.InsertRule)

	if cfg.cfg.InboundInterceptionMode == "TPROXY" {
		// save packet mark set by envoy.filters.listener.original_src as connection mark
		cfg.ruleBuilder.AppendRule("PREROUTING", "mangle",
			"ip protocol", "tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"counter", "CT", "mark set mark")
		// If the packet is already marked with 1337, then return. This is to prevent mark envoy --> app traffic again.
		cfg.ruleBuilder.AppendRule("OUTPUT", "mangle",
			"oifname", "lo",
			"ip protocol", "tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"counter", "RETURN")
		for _, uid := range split(cfg.cfg.ProxyUID) {
			// mark outgoing packets from envoy to workload by pod ip
			// app call VIP --> envoy outbound -(mark 1338)-> envoy inbound --> app
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", "OUTPUT", "mangle",
				"oifname", "lo",
				"ip protocol", "tcp",
				"ip daddr", "!=", constants.IPVersionSpecific,
				"skuid", uid,
				"counter", "meta",
				"mark set", constants.OutboundMark)
		}
		for _, gid := range split(cfg.cfg.ProxyGID) {
			// mark outgoing packets from envoy to workload by pod ip
			// app call VIP --> envoy outbound -(mark 1338)-> envoy inbound --> app
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", "OUTPUT", "mangle",
				"oifname", "lo",
				"ip protocol", "tcp",
				"ip daddr", "!=", constants.IPVersionSpecific,
				"skgid", gid,
				"counter", "meta",
				"mark set", constants.OutboundMark)
		}
		// mark outgoing packets from workload, match it to policy routing entry setup for TPROXY mode
		cfg.ruleBuilder.AppendRule("OUTPUT", "mangle",
			"ip protocol", "tcp",
			"CT", "mark", cfg.cfg.InboundTProxyMark,
			"counter", "meta",
			"mark", "set", "CT", "mark")
		// prevent infinite redirect
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, "mangle", 1,
			"ip protocol", "tcp",
			"mark", cfg.cfg.InboundTProxyMark,
			"counter", "RETURN")
		// prevent intercept traffic from envoy/pilot-agent ==> app by 127.0.0.6 --> podip
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, "mangle", 2,
			"iifname", "lo",
			"ip protocol", "tcp",
			"ip daddr", "127.0.0.6/32",
			"counter", "RETURN")
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, "mangle", 2,
			"iifname", "lo",
			"ip protocol", "tcp",
			"ip daddr", "::6/128",
			"counter", "RETURN")
		// prevent intercept traffic from app ==> app by pod ip
		cfg.ruleBuilder.InsertRule(constants.IstioInboundChain, "mangle", 3,
			"iifname", "lo",
			"ip protocol", "tcp",
			"mark", "!=", constants.OutboundMark,
			"counter", "RETURN")
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
	nft.AppendRule("OUTPUT", "raw", "counter", "jump", constants.IstioOutputDNSChain)

	// Conditionally insert jumps for V6 and V4 - we may have DNS capture enabled for V4 servers but not V6, or vice versa.
	// This avoids creating no-op jumps in v6 if we only need them in v4.
	//
	// TODO we should probably *conditionally* create jumps if and only if rules exist in the jumped-to table,
	// in a more automatic fashion.
	if captureAllDNS || len(dnsServersV4) > 0 {
		nft.AppendRule(constants.IstioOutputChain, "nat", "counter", "jump", constants.IstioOutputDNSChain)
	}

	if captureAllDNS || len(dnsServersV6) > 0 {
		nft.AppendRule(constants.IstioOutputChain, "nat", "counter", "jump", constants.IstioOutputDNSChain)
	}

	if captureAllDNS {
		// Redirect all TCP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(
			constants.IstioOutputDNSChain, "nat",
			"ip protocol", "tcp",
			"tcp dport", "53",
			"counter", "REDIRECT",
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
				constants.IstioOutputDNSChain, "nat",
				"ip daddr", s+"/32",
				"tcp dport", "53",
				"counter", "REDIRECT",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendRule(
				constants.IstioOutputDNSChain, "nat",
				"ip daddr", s+"/128",
				"tcp dport", "53",
				"counter", "REDIRECT",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
	}

	if captureAllDNS {
		// Redirect all UDP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(constants.IstioOutputDNSChain, "nat",
			"udp dport", "53",
			"counter", "REDIRECT",
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
			nft.AppendRule(constants.IstioOutputDNSChain, "nat",
				"ip daddr", s+"/32",
				"udp dport", "53",
				"counter", "REDIRECT",
				"to", ":"+constants.IstioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendRule(constants.IstioOutputDNSChain, "nat",
				"ip daddr", s+"/128",
				"udp dport", "53",
				"counter", "REDIRECT",
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
		nft.AppendRule(constants.IstioOutputDNSChain, "raw",
			"udp dport", "53",
			"meta",
			"skuid", uid,
			"CT", "zone", "set", "1")
		// Packets with src port 15053 from istio to zone 2. These are Istio response packets to application clients
		nft.AppendRule(constants.IstioOutputDNSChain, "raw",
			"udp sport", "15053",
			"meta",
			"skuid", uid,
			"CT", "zone", "set", "2")
	}
	for _, gid := range split(proxyGID) {
		// Packets with dst port 53 from istio to zone 1. These are Istio calls to upstream resolvers
		nft.AppendRule(constants.IstioOutputDNSChain, "raw",
			"udp dport", "53",
			"meta",
			"skgid", gid,
			"CT", "zone", "set", "1")
		// Packets with src port 15053 from istio to zone 2. These are Istio response packets to application clients
		nft.AppendRule(constants.IstioOutputDNSChain, "raw",
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
		nft.AppendRule("PREROUTING", "raw", "counter", "jump", constants.IstioInboundChain)
		// Not specifying destination address is useful for the CNI case where pod DNS server address cannot be decided.

		// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
		nft.AppendRule(constants.IstioOutputDNSChain, "raw",
			"udp dport", "53",
			"CT", "zone", "set", "2")
		// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
		nft.AppendRule(constants.IstioInboundChain, "raw",
			"udp sport", "53",
			"CT", "zone", "set", "1")
	} else {

		if len(dnsServersV4) != 0 {
			nft.AppendRule("PREROUTING", "raw", "counter", "jump", constants.IstioInboundChain)
		}
		// Go through all DNS servers in etc/resolv.conf and mark the packets based on these destination addresses.
		for _, s := range dnsServersV4 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendRule(constants.IstioOutputDNSChain, "raw",
				"udp dport", "53",
				"ip daddr", s+"/32",
				"CT", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendRule(constants.IstioInboundChain, "raw",
				"udp sport", "53",
				"ip daddr", s+"/32",
				"CT", "zone", "set", "1")
		}

		if len(dnsServersV6) != 0 {
			nft.AppendRule("PREROUTING", "raw", "counter", "jump", constants.IstioInboundChain)
		}
		for _, s := range dnsServersV6 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendRule(constants.IstioOutputDNSChain, "raw", "-p",
				"udp dport", "53",
				"ip daddr", s+"/128",
				"CT", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendRule(constants.IstioInboundChain, "raw",
				"udp sport", "53",
				"ip daddr", s+"/128",
				"CT", "zone", "set", "1")
		}
	}
}

func (cfg *NftablesConfigurator) handleOutboundPortsInclude() {
	if cfg.cfg.OutboundPortsInclude != "" {
		for _, port := range split(cfg.cfg.OutboundPortsInclude) {
			cfg.ruleBuilder.AppendRule(
				constants.IstioOutputChain, "nat", "tcp dport", port, "counter", "jump", constants.IstioRedirectChain)
		}
	}
}

func (cfg *NftablesConfigurator) handleCaptureByOwnerGroup(filter config.InterceptFilter) {
	if filter.Except {
		for _, group := range filter.Values {
			cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
				"skgid", group,
				"counter", "RETURN")
		}
	} else {
		groupIsNoneOf := CombineMatchers(filter.Values, func(group string) []string {
			return []string{"skgid", "!=", group}
		})
		cfg.ruleBuilder.AppendRule(constants.IstioOutputChain, "nat",
			append(groupIsNoneOf, "counter", "RETURN")...)
	}
}

func (cfg *NftablesConfigurator) executeCommands() error {
	// We require (or rather, knftables.New does) that the nft binary be version 1.0.1
	// or later, because versions before that would always attempt to parse the entire
	// nft ruleset at startup, even if you were only operating on a single table.
	// That's bad, because in some cases, new versions of nft have added new rule
	// types in ways that triggered bugs in older versions of nft, causing them to
	// crash.

	for table, chains := range cfg.chainBuilder.Chains {
		nft, err := knftables.New(knftables.IPv4Family, table)
		if err != nil {
			return err
		}
		tx := nft.NewTransaction()

		// Ensure that our table and chains exist.
		tx.Add(&knftables.Table{})

		for _, chain := range chains {
			tx.Add(&chain)
			tx.Flush(&chain)
		}

		// Add rules for each table
		for tableName, rules := range cfg.ruleBuilder.Rules {
			if tableName == table {
				for _, rule := range rules {
					tx.Add(&rule)
				}
			}
		}

		// Apply changes in this transaction
		if err := nft.Run(context.TODO(), tx); err != nil {
			return err
		}
	}

	return nil
}
