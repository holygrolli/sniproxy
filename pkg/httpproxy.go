package sniproxy

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
)

var passthruRequestHeaderKeys = [...]string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Cookie",
	"Referer",
	"User-Agent",
}

var passthruResponseHeaderKeys = [...]string{
	"Content-Encoding",
	"Content-Language",
	"Content-Type",
	"Cache-Control", // TODO: Is this valid in a response?
	"Date",
	"Etag",
	"Expires",
	"Last-Modified",
	"Location",
	"Server",
	"Vary",
}

// RunHTTP starts the HTTP proxy server on the specified bind address.
// The bind address should be in the format "0.0.0.0:80" or similar.
// This function blocks and should typically be run in a goroutine.
func RunHTTP(c *Config, bind string, l zerolog.Logger) {
	handler := http.NewServeMux()
	l = l.With().Str("service", "http").Str("listener", bind).Logger()

	handler.HandleFunc("/", handle80(c, l))

	s := &http.Server{
		Addr:           bind,
		Handler:        handler,
		ReadTimeout:    HTTPReadTimeout,
		WriteTimeout:   HTTPWriteTimeout,
		MaxHeaderBytes: 1 << 20,
	}

	l.Info().Str("bind", bind).Msg("starting http server")
	if err := s.ListenAndServe(); err != nil {
		l.Error().Msg(err.Error())
		panic(-1)
	}
}

// serveStatusPage serves a simple HTML page showing the proxy's public IP information
func serveStatusPage(w http.ResponseWriter, ipv4, ipv6, dnsName string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := `<!DOCTYPE html>
<html>
<head>
	<title>SNI Proxy Status</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
		.container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		h1 { color: #333; }
		.info { margin: 20px 0; }
		.label { font-weight: bold; color: #666; }
		.value { color: #333; font-family: monospace; background-color: #f0f0f0; padding: 4px 8px; border-radius: 4px; }
		.na { color: #999; font-style: italic; }
	</style>
</head>
<body>
	<div class="container">
		<h1>SNI Proxy Status</h1>
		<div class="info">
			<span class="label">IPv4 Address:</span> `

	if ipv4 != "" {
		html += `<span class="value">` + ipv4 + `</span>`
	} else {
		html += `<span class="na">Not configured</span>`
	}

	html += `
		</div>
		<div class="info">
			<span class="label">IPv6 Address:</span> `

	if ipv6 != "" {
		html += `<span class="value">` + ipv6 + `</span>`
	} else {
		html += `<span class="na">Not configured</span>`
	}

	html += `
		</div>
		<div class="info">
			<span class="label">DNS Name:</span> `

	if dnsName != "" {
		html += `<span class="value">` + dnsName + `</span>`
	} else {
		html += `<span class="na">Not configured</span>`
	}

	html += `
		</div>
	</div>
</body>
</html>`

	w.Write([]byte(html))
}

func handle80(c *Config, l zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.ReceivedHTTP.Inc(1)

		// Get the TCP address from RemoteAddr
		remoteAddr := r.RemoteAddr

		connInfo := acl.ConnInfo{
			SrcIP:  &net.TCPAddr{IP: net.ParseIP(remoteAddr[:strings.LastIndex(remoteAddr, ":")])},
			Domain: r.Host,
		}
		acl.MakeDecision(&connInfo, c.ACL)
		if connInfo.Decision == acl.Reject || connInfo.Decision == acl.OriginIP {
			l.Info().Str("src_ip", remoteAddr).Msgf("rejected request")
			http.Error(w, "Could not reach origin server", 403)
			return
		}
		// Get current public IPs (will auto-refresh if needed)
		ipv4, ipv6 := c.GetPublicIPs()
		
		// Check if request is to the proxy's own domains (public IPs, DNS name, or local domain suffixes)
		// Extract hostname without port for comparison
		hostWithoutPort := r.Host
		if colonIndex := strings.LastIndex(r.Host, ":"); colonIndex != -1 {
			// Check if this is an IPv6 address or hostname with port
			if !strings.HasPrefix(r.Host, "[") {
				// Not an IPv6 address, so extract hostname
				hostWithoutPort = r.Host[:colonIndex]
			}
		}

		if c.IsStatusPageDomain(hostWithoutPort) {
			l.Info().Str("host", r.Host).Msg("serving status page for request to sniproxy domain")
			serveStatusPage(w, ipv4, ipv6, c.PublicIpDns)
			return
		}

		l.Info().Str("method", r.Method).Str("host", r.Host).Str("url", r.URL.String()).Msg("request received")

		// Construct filtered header to send to origin server
		hh := http.Header{}
		for _, hk := range passthruRequestHeaderKeys {
			if hv, ok := r.Header[hk]; ok {
				hh[hk] = hv
			}
		}

		// Construct request to send to origin server
		rr := http.Request{
			Method:        r.Method,
			URL:           r.URL,
			Header:        hh,
			Body:          r.Body,
			ContentLength: r.ContentLength,
			Close:         r.Close,
		}
		rr.URL.Scheme = "http"
		rr.URL.Host = r.Host

		// setting up this dialer will enable to use the upstream SOCKS5 if configured
		transport := http.Transport{
			Dial: c.Dialer.Dial,
		}

		// Forward request to origin server
		resp, err := transport.RoundTrip(&rr)
		if err != nil {
			l.Error().Err(err).Str("host", r.Host).Msg("failed to forward HTTP request")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		l.Info().Msgf("http response with status_code %s", resp.Status)

		// Transfer filtered header from origin server -> client
		respH := w.Header()
		for _, hk := range passthruResponseHeaderKeys {
			if hv, ok := resp.Header[hk]; ok {
				respH[hk] = hv
			}
		}
		c.ProxiedHTTP.Inc(1)
		w.WriteHeader(resp.StatusCode)

		// Transfer response from origin server -> client
		io.Copy(w, resp.Body)
	}
}
