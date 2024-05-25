package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	tls "github.com/refraction-networking/utls"
)

// test4 is a uTLS connection using:
// TCP
// default cipher suites
// forced TLS1.3
// default elliptic curve preferences
// utls.HelloChrome_Auto
func test4(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) {
	l = l.With("test", "test4", "ip", addrPort.Addr().String())
	// Initiate TCP connection
	tcpDialer := net.Dialer{
		Timeout:       5 * time.Second,
		LocalAddr:     nil,
		FallbackDelay: -1, // disable happy-eyeballs
		KeepAlive:     15, // default
		Resolver:      &net.Resolver{PreferGo: true},
	}
	tcpDialer.SetMultipathTCP(false)

	tcpConn, err := tcpDialer.DialContext(ctx, "tcp", addrPort.String())
	if err != nil {
		l.Error(err.Error())
		return
	}
	defer tcpConn.Close()

	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
	}

	tlsConn := tls.UClient(tcpConn, &tlsConfig, tls.HelloChrome_Auto)
	defer tlsConn.Close()

	// Explicitly run the handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.Error(err.Error())
		return
	}

	tlsState := tlsConn.ConnectionState()
	l.Info("success", "handshake", tlsState.HandshakeComplete)
}
