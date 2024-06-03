package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

type TestOptions struct {
	ResolveIPv4 bool
	ResolveIPv6 bool
	ManualIP    netip.Addr
	Port        uint16
	SNI         string
	Repeat      uint
}

type TestResult struct {
	AddrPort netip.AddrPort
	SNI      string
	Attempts []TestAttemptResult
}

type TestAttemptResult struct {
	TransportEstablishDuration time.Duration
	TLSHandshakeDuration       time.Duration
	err                        error
}

type testFunc func(context.Context, *slog.Logger, netip.AddrPort, string) TestAttemptResult

var testList map[string]testFunc = map[string]testFunc{
	GetFunctionName(test_TCP_TLS12_Default):                         test_TCP_TLS12_Default,
	GetFunctionName(test_TCP_TLS13_Default):                         test_TCP_TLS13_Default,
	GetFunctionName(test_TCP_TLS_warp_plus_custom):                  test_TCP_TLS_warp_plus_custom,
	GetFunctionName(test_TCP_TLS13_UTLS_ChromeAuto_Default):         test_TCP_TLS13_UTLS_ChromeAuto_Default,
	GetFunctionName(test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment): test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment,
	GetFunctionName(test_QUIC_TLS13_UQUIC_Chrome_115_Default):       test_QUIC_TLS13_UQUIC_Chrome_115_Default,
}

func runTests(ctx context.Context, l *slog.Logger, to TestOptions) error {
	l = l.With("sni", to.SNI, "port", to.Port)

	testAddrPorts := []netip.AddrPort{}
	if to.ManualIP == netip.IPv4Unspecified() {
		l.Debug("manual IP not specified, attempting DNS resolution")

		// Resolve DNS
		var err error
		v4, v6, err := resolve(ctx, to.SNI, to.ResolveIPv4, to.ResolveIPv6)
		if err != nil {
			return fmt.Errorf("failed to resolve SNI: %w", err)
		}

		if to.ResolveIPv4 && v4 != netip.IPv4Unspecified() {
			testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(v4, to.Port))
		}

		if to.ResolveIPv6 && v6 != netip.IPv6Unspecified() {
			testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(v6, to.Port))
		}
	} else {
		testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(to.ManualIP, to.Port))
	}

	results := make(map[string][]TestResult)
	for name, test := range testList {
		resultsPerTest := make([]TestResult, len(testAddrPorts))
		for x, addrPort := range testAddrPorts {
			tr := TestResult{AddrPort: addrPort, SNI: to.SNI, Attempts: make([]TestAttemptResult, to.Repeat)}
			for i := uint(0); i < to.Repeat; i++ {
				tr.Attempts[i] = test(ctx, l, addrPort, to.SNI)
				time.Sleep(1 * time.Second)
			}
			resultsPerTest[x] = tr
		}
		results[name] = resultsPerTest
	}

	printTable(results)

	return nil
}

func printTable(results map[string][]TestResult) {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Test", "SNI", "AddressPort", "Success", "TransportEstablishTime", "TLSHandshakeTime")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, testName := range keys {
		testResults := results[testName]
		for _, testResult := range testResults {
			for i, attempt := range testResult.Attempts {
				tbl.AddRow(
					fmt.Sprintf("%s - %d", testName, i+1),
					testResult.SNI,
					testResult.AddrPort,
					attempt.err == nil,
					attempt.TransportEstablishDuration,
					attempt.TLSHandshakeDuration,
				)
			}
			tbl.AddRow()
		}
	}

	tbl.Print()
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

func GetFunctionName(temp interface{}) string {
	strs := strings.Split((runtime.FuncForPC(reflect.ValueOf(temp).Pointer()).Name()), ".")
	return strs[len(strs)-1]
}
