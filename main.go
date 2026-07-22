package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/carlmjohnson/versioninfo"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const appName = "heybabe"

var (
	version   = ""
	logLevels = []string{
		slog.LevelDebug.String(),
		slog.LevelInfo.String(),
		slog.LevelWarn.String(),
		slog.LevelError.String(),
	}
)

func main() {
	fs := ff.NewFlagSet(appName)
	var (
		v4       = fs.BoolShort('4', "only resolve IPv4 (only works when IP is not set)")
		v6       = fs.BoolShort('6', "only resolve IPv6 (only works when IP is not set)")
		sni      = fs.StringLong("sni", "", "tls sni (if IP flag not provided, this SNI will be resolved by system DNS)")
		host     = fs.StringLong("host", "", "http host (defaults to sni)")
		port     = fs.UintLong("port", 443, "tls port")
		ip       = fs.StringLong("ip", "", "manually provide IP (no DNS lookup)")
		repeat   = fs.UintLong("repeat", 1, "number of times to repeat each test")
		logLevel = fs.StringEnumLong("loglevel", fmt.Sprintf("specify a log level (valid values: %s)", logLevels), logLevels...)
		logJson  = fs.Bool('j', "json", "log in json format")
		verFlag  = fs.BoolLong("version", "displays version number")
	)

	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *verFlag {
		if version == "" {
			version = versioninfo.Short()
		}
		fmt.Fprintf(os.Stderr, "%s\n", version)
		os.Exit(0)
	}

	var lOpts *slog.HandlerOptions
	switch *logLevel {
	case slog.LevelDebug.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelDebug}
	case slog.LevelInfo.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelInfo}
	case slog.LevelWarn.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelWarn}
	case slog.LevelError.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelError}
	}

	var lHandler slog.Handler
	if *logJson {
		lHandler = slog.NewJSONHandler(os.Stdout, lOpts)
	} else {
		lHandler = slog.NewTextHandler(os.Stdout, lOpts)
	}

	l := slog.New(lHandler)

	// Make sure that port does not exceed 65535
	if *port > uint(^uint16(0)) {
		fatal(l, fmt.Errorf("invalid port %v", *port))
	}

	if *sni == "" {
		fatal(l, errors.New("must specify SNI"))
	}
	if *host == "" {
		*host = *sni
	}

	addr := netip.IPv4Unspecified()
	if *ip != "" {
		if *v4 || *v6 {
			fatal(l, errors.New("cannot set ip and -4 or -6"))
		}
		addr, err = netip.ParseAddr(*ip)
		if err != nil {
			fatal(l, err)
		}
	} else if *v4 == *v6 {
		// Essentially doing XNOR to make sure that if they are both false
		// or both true, just set them both true.
		*v4, *v6 = true, true
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		defer cancel()

		to := TestOptions{
			ResolveIPv4: *v4,
			ResolveIPv6: *v6,
			ManualIP:    addr.Unmap(),
			Port:        uint16(*port),
			SNI:         *sni,
			Host:        *host,
			Repeat:      *repeat,
		}

		if err := runTests(ctx, l, to); err != nil {
			fatal(l, err)
		}
	}()

	<-ctx.Done()
}

func fatal(l *slog.Logger, err error) {
	l.Error(err.Error())
	os.Exit(1)
}
