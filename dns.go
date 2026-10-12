package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TUNResolver forwards DNS resolution through the tunnel
type TUNResolver struct {
	vt *VirtualTun
	// dialContext, when set, is used instead of vt.Tnet (tests).
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// defaultEDNSSize fits an IPv6 datagram on a 1280-byte path (typical WG inner MTU).
const defaultEDNSSize = 1232

// dnsUDPReadSize is the UDP receive buffer. It is larger than the advertised
// EDNS payload so a non-compliant server that still sends more is not sliced.
const dnsUDPReadSize = 4096

const dnsQueryTimeout = 5 * time.Second

// Resolve resolves a hostname using DNS over the virtual tunnel interface.
// It prefers IPv4 (A records), but falls back to IPv6 (AAAA) if no A is found.
func (r *TUNResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if r.vt == nil || r.vt.Conf == nil {
		return ctx, nil, errors.New("no DNS servers configured")
	}
	if len(r.vt.Conf.DNS) == 0 {
		return r.resolveSystem(ctx, name)
	}

	// Normalize: ensure trailing dot for absolute queries
	originalName := name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// List of names to try: original + appended search domains if unqualified
	var namesToQuery []string
	if strings.Count(strings.TrimSuffix(originalName, "."), ".") == 0 && len(r.vt.Conf.SearchDomains) > 0 {
		for _, domain := range r.vt.Conf.SearchDomains {
			full := strings.TrimSuffix(originalName, ".") + "." + strings.TrimPrefix(domain, ".") + "."
			namesToQuery = append(namesToQuery, full)
		}
	}
	namesToQuery = append(namesToQuery, name) // Fallback to original

	// Query A before AAAA by default, but flip the order on a v6-only tunnel:
	// an A answer would be undialable there anyway, so asking for it first
	// would just cost a wasted round trip on every single lookup.
	qtypes := [2]uint16{dns.TypeA, dns.TypeAAAA}
	if r.preferAAAAFirst() {
		qtypes[0], qtypes[1] = dns.TypeAAAA, dns.TypeA
	}

	// Try each configured DNS server in order so a down/unreachable server
	// falls back to the next one instead of failing
	var lastErr error
	for _, server := range r.vt.Conf.DNS {
		dnsServer := net.JoinHostPort(server.String(), "53")

		for _, qtype := range qtypes {
			for _, qname := range namesToQuery {
				ip, err := r.queryDNS(ctx, dnsServer, qname, qtype)
				if err == nil && ip != nil {
					r.logVerbosef("dns: resolved name=%s -> %s via %s", name, ip, dnsServer)
					return ctx, ip, nil
				}
				if err != nil {
					lastErr = err
				}
			}
		}
	}

	if lastErr != nil {
		err := fmt.Errorf(
			"no A or AAAA records found after trying %d DNS server(s): %w",
			len(r.vt.Conf.DNS), lastErr,
		)
		r.logErrorf("dns: failed to resolve name=%s: %v", name, err)
		return ctx, nil, err
	}
	err := errors.New("no A or AAAA records found after trying search domains")
	r.logErrorf("dns: failed to resolve name=%s: %v", name, err)
	return ctx, nil, err
}

func (r *TUNResolver) logVerbosef(format string, args ...any) {
	if r.vt != nil && r.vt.Logger != nil && r.vt.Logger.Verbosef != nil {
		r.vt.Logger.Verbosef(format, args...)
	}
}

func (r *TUNResolver) logErrorf(format string, args ...any) {
	if r.vt != nil && r.vt.Logger != nil && r.vt.Logger.Errorf != nil {
		r.vt.Logger.Errorf(format, args...)
	}
}

// preferAAAAFirst reports whether to query AAAA before A. Only true when the
// tunnel interface has an IPv6 address and no IPv4 address of its own.
func (r *TUNResolver) preferAAAAFirst() bool {
	if r.vt == nil || r.vt.Conf == nil {
		return false
	}
	hasV4, hasV6 := false, false
	for _, a := range r.vt.Conf.Address {
		switch {
		case a.Is4() || a.Is4In6():
			hasV4 = true
		case a.Is6():
			hasV6 = true
		}
	}
	return hasV6 && !hasV4
}

// resolveSystem uses the OS resolver (underlay / "local" FakeDNS transport)
// when the tunnel config has no DNS servers. Prefer A, then AAAA.
func (r *TUNResolver) resolveSystem(ctx context.Context, name string) (context.Context, net.IP, error) {
	host := strings.TrimSuffix(name, ".")
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err == nil {
		for _, ip := range ips {
			if ip != nil {
				return ctx, ip, nil
			}
		}
	}
	ips, err = net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err == nil {
		for _, ip := range ips {
			if ip != nil {
				return ctx, ip, nil
			}
		}
	}
	resolveErr := errors.New("no A or AAAA records found via system DNS")
	r.logErrorf("dns: failed to resolve name=%s: %v", name, resolveErr)
	return ctx, nil, resolveErr
}

func ednsSizeForMTU(mtu int) uint16 {
	if mtu <= 0 {
		return defaultEDNSSize
	}
	n := mtu - 48 // IPv6 header + UDP
	if n > defaultEDNSSize {
		n = defaultEDNSSize
	}
	if n < dns.MinMsgSize {
		n = dns.MinMsgSize
	}
	return uint16(n)
}

func (r *TUNResolver) ednsSize() uint16 {
	mtu := 0
	if r != nil && r.vt != nil && r.vt.Conf != nil {
		mtu = r.vt.Conf.MTU
	}
	return ednsSizeForMTU(mtu)
}

func (r *TUNResolver) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if r.dialContext != nil {
		return r.dialContext(ctx, network, address)
	}
	if r.vt == nil || r.vt.Tnet == nil {
		return nil, errors.New("no tunnel network")
	}
	return r.vt.Tnet.DialContext(ctx, network, address)
}

// queryDNS sends a DNS query of the specified type and returns the first matching IP.
// UDP first with a path-sized EDNS0 OPT; TCP if the UDP reply is truncated,
// unparseable, or has no A/AAAA.
func (r *TUNResolver) queryDNS(ctx context.Context, dnsServer, name string, qtype uint16) (net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true
	msg.Id = uint16(rand.Intn(65536))
	msg.SetEdns0(r.ednsSize(), false)

	resp, err := r.roundTrip(ctx, "udp", dnsServer, msg)
	ip := firstIP(resp, qtype)
	if err == nil && ip != nil && (resp == nil || !resp.Truncated) {
		return ip, nil
	}
	if err != nil && resp == nil {
		return nil, err
	}

	tcpResp, tcpErr := r.roundTrip(ctx, "tcp", dnsServer, msg)
	if tcpIP := firstIP(tcpResp, qtype); tcpErr == nil && tcpIP != nil {
		return tcpIP, nil
	}
	if ip != nil {
		return ip, nil
	}
	if tcpErr != nil {
		return nil, tcpErr
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("no matching DNS records found")
}

func (r *TUNResolver) roundTrip(ctx context.Context, network, server string, msg *dns.Msg) (*dns.Msg, error) {
	conn, err := r.dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(dnsQueryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	c := &dns.Conn{Conn: conn}
	if network == "udp" || network == "udp4" || network == "udp6" {
		c.UDPSize = dnsUDPReadSize
	}
	if err := c.WriteMsg(msg); err != nil {
		return nil, err
	}
	resp, err := c.ReadMsg()
	if resp != nil && resp.Id != msg.Id {
		return resp, errors.New("mismatched DNS response ID")
	}
	return resp, err
}

func firstIP(resp *dns.Msg, qtype uint16) net.IP {
	if resp == nil {
		return nil
	}
	for _, ans := range resp.Answer {
		switch qtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				return a.A
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				return aaaa.AAAA
			}
		}
	}
	return nil
}
