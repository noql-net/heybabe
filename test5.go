package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/markpash/heybabe/bepass/tlsfrag"
	tls "github.com/refraction-networking/utls"
)

// test5 is a uTLS connection using:
// TCP
// default cipher suites
// forced TLS1.3
// default elliptic curve preferences
// utls.HelloChrome_Auto
// And the bepass fragmenting TCP connection!
func test5(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) error {
	l = l.With("test", "test5", "ip", addrPort.Addr().String())
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

	// bepass frag settings
	bsl := [2]int{2000, 2000} // ChunksLengthBeforeSni
	sl := [2]int{1, 2}        // SniChunksLength
	asl := [2]int{1, 2}       // ChunksLengthAfterSni
	delay := [2]int{10, 20}   // DelayBetweenChunks

	tcpTlsFragConn := tlsfrag.New(tcpConn, bsl, sl, asl, delay)

	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
	}

	tlsConn := tls.UClient(tcpTlsFragConn, &tlsConfig, tls.HelloChrome_Auto)
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
