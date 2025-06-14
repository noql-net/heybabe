# heybabe

TLS ClientHello testing tool

## Basics

```sh
heybabe --sni twitter.com
```

To manually provide an IP address and avoid DNS lookup:

```sh
heybabe --sni twitter.com --ip 1.2.3.4
```

To specify a non-default port:

```sh
heybabe --sni twitter.com --port 8443
```

To repeat a test multiple times:

```sh
heybabe --sni twitter.com --repeat 2
```

### Usage

```none
NAME
  heybabe

FLAGS
  -4                      only resolve IPv4 (only works when IP is not set)
  -6                      only resolve IPv6 (only works when IP is not set)
      --sni STRING        tls sni (if IP flag not provided, this SNI will be resolved by system DNS)
      --port UINT         tls port (default: 443)
      --ip STRING         manually provide IP (no DNS lookup)
      --repeat UINT       number of times to repeat each test (default: 1)
      --loglevel STRING   specify a log level (valid values: [DEBUG INFO WARN ERROR]) (default: DEBUG)
  -j, --json              log in json format
      --version           displays version number
```
