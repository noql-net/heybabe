package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type connWithState interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

func measureTTFB(ctx context.Context, conn net.Conn, host string) (ttfb time.Duration, err error) {
	dl, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}

	alpn, err := getALPN(conn)
	if err != nil {
		return 0, fmt.Errorf("passed a non-tls connection")
	}
	switch alpn {
	case "http/1.1", "":
		return measureTTFBH1(ctx, conn, host)
	case "h2":
		return measureTTFBH2(ctx, conn, host)
	default:
		return 0, fmt.Errorf("unsupported ALPN protocol: %q", alpn)
	}

}

func getALPN(conn net.Conn) (string, error) {
	switch c := conn.(type) {
	case *tls.Conn:
		return c.ConnectionState().NegotiatedProtocol, nil
	case *utls.UConn:
		return c.ConnectionState().NegotiatedProtocol, nil
	default:
		return "", fmt.Errorf("passed a non-TLS conn: %T", conn)
	}
}

func measureTTFBH1(ctx context.Context, conn net.Conn, host string) (ttfb time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	if err != nil {
		return 0, err
	}
	req.Host = host

	start := time.Now()
	if err = req.Write(conn); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	if _, err = reader.Peek(1); err != nil {
		return time.Since(start), err
	}
	ttfb = time.Since(start)

	dummyReq := &http.Request{Method: "GET"}
	_, err = http.ReadResponse(reader, dummyReq)
	return ttfb, err
}

func measureTTFBH2(ctx context.Context, conn net.Conn, host string) (ttfb time.Duration, err error) {
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		return 0, err
	}
	defer cc.Close()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	if err != nil {
		return 0, err
	}
	req.Host = host

	start := time.Now()
	_, err = cc.RoundTrip(req)
	ttfb = time.Since(start)
	return ttfb, err
}
