package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseTrustedProxies parses a comma- or whitespace-separated list of CIDRs or
// bare IPs. An empty spec returns (nil, nil), meaning "use the default":
// loopback / RFC1918 / ULA peers are trusted.
func ParseTrustedProxies(spec string) ([]*net.IPNet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})

	nets := make([]*net.IPNet, 0, len(fields))
	for _, field := range fields {
		if strings.Contains(field, "/") {
			_, network, err := net.ParseCIDR(field)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", field, err)
			}
			nets = append(nets, network)
			continue
		}

		ip := net.ParseIP(field)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", field)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}

	if len(nets) == 0 {
		return nil, fmt.Errorf("no valid CIDR or IP in %q", spec)
	}
	return nets, nil
}

// ClientIP resolves the rate-limit/logging client address. Forwarding headers
// are honoured only when the TCP peer is a trusted proxy.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	host := RemoteHost(r)
	if !isTrustedProxy(host, trusted) {
		return host
	}
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	}
	return host
}

// RemoteHost returns the peer address without the ephemeral port.
func RemoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return host
}

func isTrustedProxy(host string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if trusted == nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
