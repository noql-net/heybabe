package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

type TestOptions struct {
	ResolveIPv4 bool
	ResolveIPv6 bool
	ManualIP    netip.Addr
	Port        uint16
	SNI         string
}

type testFunc func(context.Context, *slog.Logger, netip.AddrPort, string)

var testList []testFunc = []testFunc{
	test1,
	test2,
	test3,
	test4,
	test5,
}

func runTests(ctx context.Context, l *slog.Logger, to TestOptions) error {
	l = l.With("sni", to.SNI, "port", to.Port)

	v4, v6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
	if to.ManualIP == netip.IPv4Unspecified() {
		l.Debug("manual IP not specified, attempting DNS resolution")

		// Resolve DNS
		var err error
		v4, v6, err = resolve(ctx, to.SNI, to.ResolveIPv4, to.ResolveIPv6)
		if err != nil {
			return fmt.Errorf("failed to resolve SNI: %w", err)
		}
	}

	for _, test := range testList {
		if to.ManualIP != netip.IPv4Unspecified() {
			test(ctx, l, netip.AddrPortFrom(to.ManualIP, to.Port), to.SNI)
			time.Sleep(1 * time.Second)
			continue
		}

		// If the IP is not manually provided (therefore unspecified),
		// use the resolved IPs but limit tests to only the user
		// specified address families.
		if to.ResolveIPv4 && v4 != netip.IPv4Unspecified() {
			test(ctx, l, netip.AddrPortFrom(v4, to.Port), to.SNI)
		}
		if to.ResolveIPv6 && v6 != netip.IPv6Unspecified() {
			test(ctx, l, netip.AddrPortFrom(v6, to.Port), to.SNI)
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func resolve(ctx context.Context, hostname string, getv4, getv6 bool) (v4, v6 netip.Addr, err error) {
	v4, v6 = netip.IPv4Unspecified(), netip.IPv6Unspecified()

	addrs, err := (&net.Resolver{PreferGo: true}).LookupHost(ctx, hostname)
	if err != nil {
		return v4, v6, err
	}

	// I'm lazy, parse all addresses
	parsedAddrs := make([]netip.Addr, len(addrs))
	for i, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return v4, v6, err
		}
		parsedAddrs[i] = ip.Unmap()
	}

	// Find the first v4 address
	if getv4 {
		for _, addr := range parsedAddrs {
			if addr.Is4() {
				v4 = addr
				break
			}
		}
	}

	// Find the first v6 address
	if getv6 {
		for _, addr := range parsedAddrs {
			if addr.Is6() {
				v6 = addr
				break
			}
		}
	}

	return v4, v6, nil
}
