package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"runtime"
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

// Represents a single test function and its label.
type testCase struct {
	fn    testFunc
	label string
}

// Holds all tests in the exact order we want to execute and display.
var testSuite = []testCase{
	{fn: test_TCP_TLS12_Default, label: "Default - TCP - TLS 1.2"},
	{fn: test_TCP_TLS13_Default, label: "Default - TCP - TLS 1.3"},
	{fn: test_TCP_TLS13_UTLS_ChromeAuto_Default, label: "Default - TCP - TLS 1.3 - uTLS ChromeAuto"},
	{fn: test_QUIC_TLS13_UQUIC_Chrome_115_Default, label: "Default - QUIC - TLS 1.3 - uQUIC Chrome"},
	{fn: test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment, label: "Bepass Fragment - TCP - TLS 1.3 - uTLS ChromeAuto"},
	{fn: test_TCP_TLS_warp_plus_custom, label: "WarpPlus Custom - TCP - TLS 1.2"},
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
		l.Debug("manual IP specified, proceeding with the provided IP")
		testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(to.ManualIP, to.Port))
	}

	results := make(map[string][]TestResult)
	labelOrder := make([]string, 0, len(testSuite))

	for _, tc := range testSuite {
		test := tc.fn
		resultsPerTest := make([]TestResult, len(testAddrPorts))
		for x, addrPort := range testAddrPorts {
			tr := TestResult{AddrPort: addrPort, SNI: to.SNI, Attempts: make([]TestAttemptResult, to.Repeat)}
			for i := uint(0); i < to.Repeat; i++ {
				// Create a context with 10-second timeout for each individual test
				testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				tr.Attempts[i] = test(testCtx, l, addrPort, to.SNI)
				cancel() // Always cancel to release resources
				time.Sleep(2 * time.Second)
			}
			resultsPerTest[x] = tr
		}
		results[tc.label] = resultsPerTest
		labelOrder = append(labelOrder, tc.label)
		// 2-second delay between different test types
		time.Sleep(2 * time.Second)
	}

	printTable(results, labelOrder)

	return nil
}

func printTable(results map[string][]TestResult, order []string) {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Test", "SNI", "AddressPort", "Success", "TransportEstablishTime", "TLSHandshakeTime")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, testName := range order {
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
		}
	}

	fmt.Println("")
	tbl.Print()
	fmt.Println("")
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
