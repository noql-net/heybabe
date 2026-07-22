package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	// This is for systems that don't have a good set of roots. (update often)
	_ "golang.org/x/crypto/x509roots/fallback"

	quic "github.com/refraction-networking/uquic"
	tls "github.com/refraction-networking/utls"
)

// test_QUIC_TLS13_UQUIC_Chrome_115_Default
func test_QUIC_TLS13_UQUIC_Chrome_115_Default(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string, host string) TestAttemptResult {
	counter, _, _, _ := runtime.Caller(0)
	l = l.With("test", strings.Split(runtime.FuncForPC(counter).Name(), ".")[1], "ip", addrPort.Addr().String())

	res := TestAttemptResult{}

	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
		NextProtos:         []string{"h3"},
	}

	quicConf := &quic.Config{}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		l.Error(err.Error())
		res.err = err
		return res
	}

	quicSpec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		l.Error(err.Error())
		res.err = err
		return res
	}

	ut := &quic.UTransport{
		Transport: &quic.Transport{Conn: udpConn},
		QUICSpec:  &quicSpec,
	}

	t0 := time.Now()
	quicConn, err := ut.Dial(ctx, net.UDPAddrFromAddrPort(addrPort), &tlsConfig, quicConf)
	if err != nil {
		l.Error(err.Error())
		res.err = err
		return res
	}
	defer quicConn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	res.TransportEstablishDuration = time.Since(t0)

	l.Info("handshake success", "handshake", quicConn.ConnectionState().TLS.HandshakeComplete)
	l.Warn("TTFB test not yet implemented for QUIC")

	return res
}
