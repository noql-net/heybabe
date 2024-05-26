package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"time"

	// This is for systems that don't have a good set of roots. (update often)
	_ "golang.org/x/crypto/x509roots/fallback"
)

// test2 is a go crypto/tls connection using:
// TCP
// default cipher suites
// forced TLS1.3
// default elliptic curve preferences
func test2(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) error {
	l = l.With("test", "test2", "ip", addrPort.Addr().String())
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
		return err
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

	tlsConn := tls.Client(tcpConn, &tlsConfig)
	defer tlsConn.Close()

	// Explicitly run the handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.Error(err.Error())
		return err
	}

	tlsState := tlsConn.ConnectionState()
	l.Info("success", "handshake", tlsState.HandshakeComplete)
	return nil
}
