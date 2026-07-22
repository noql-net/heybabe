package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	// This is for systems that don't have a good set of roots. (update often)
	_ "golang.org/x/crypto/x509roots/fallback"
)

// test_TCP_TLS13_Default is a go crypto/tls connection using:
// TCP
// default cipher suites
// forced TLS1.3
// default elliptic curve preferences
func test_TCP_TLS13_Default(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string, host string) TestAttemptResult {
	counter, _, _, _ := runtime.Caller(0)
	l = l.With("test", strings.Split(runtime.FuncForPC(counter).Name(), ".")[1], "ip", addrPort.Addr().String())

	res := TestAttemptResult{}

	// Initiate TCP connection
	tcpDialer := net.Dialer{
		Timeout:       5 * time.Second,
		LocalAddr:     nil,
		FallbackDelay: -1, // disable happy-eyeballs
		KeepAlive:     15, // default
		Resolver:      &net.Resolver{PreferGo: true},
	}
	tcpDialer.SetMultipathTCP(false)

	t0 := time.Now()
	tcpConn, err := tcpDialer.DialContext(ctx, "tcp", addrPort.String())
	if err != nil {
		l.Error(err.Error())
		res.err = err
		return res
	}
	defer tcpConn.Close()
	res.TransportEstablishDuration = time.Since(t0)

	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
	}

	tlsConn := tls.Client(tcpConn, &tlsConfig)
	defer tlsConn.Close()

	// Explicitly run the handshake
	t0 = time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.Error(err.Error())
		res.err = err
		return res
	}
	res.TLSHandshakeDuration = time.Since(t0)

	tlsState := tlsConn.ConnectionState()
	l.Info("handshake success", "handshake", tlsState.HandshakeComplete)

	ttfb, err := measureTTFB(ctx, tlsConn, host)
	if err != nil {
		res.err = err
		l.Error(err.Error())
	}
	res.TTFBDuration = ttfb

	return res
}
