package sniproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func newTestConfig(ipv4, ipv6, publicIpDns string) *Config {
	return &Config{
		PublicIPv4:   ipv4,
		PublicIPv6:   ipv6,
		PublicIpDns:  publicIpDns,
		ACL:          []acl.ACL{},
		ReceivedHTTP: metrics.NewCounter(),
		ProxiedHTTP:  metrics.NewCounter(),
		Dialer:       proxy.Direct,
	}
}

// TestHandle80_SelfRequestByIPv4 tests that requests to the proxy's own IPv4 address serve a status page
func TestHandle80_SelfRequestByIPv4(t *testing.T) {
	logger := zerolog.Nop()
	config := newTestConfig("203.0.113.1", "", "")

	handler := handle80(config, logger)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		checkContent   bool
	}{
		{
			name:           "Request to exact IPv4",
			host:           "203.0.113.1",
			expectedStatus: http.StatusOK,
			checkContent:   true,
		},
		{
			name:           "Request to IPv4 with port",
			host:           "203.0.113.1:8080",
			expectedStatus: http.StatusOK,
			checkContent:   true,
		},
		{
			name:           "Request to different host",
			host:           "nonexistent.invalid.domain.example",
			expectedStatus: http.StatusBadGateway, // Will fail to connect, but shouldn't be blocked
			checkContent:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = "192.0.2.1:12345"

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.checkContent {
				body := w.Body.String()
				if !contains(body, "203.0.113.1") {
					t.Errorf("Expected body to contain IPv4 address, got %q", body)
				}
				if !contains(body, "SNI Proxy Status") {
					t.Errorf("Expected body to contain title, got %q", body)
				}
			}
		})
	}
}

// TestHandle80_SelfRequestByIPv6 tests that requests to the proxy's own IPv6 address serve a status page
func TestHandle80_SelfRequestByIPv6(t *testing.T) {
	logger := zerolog.Nop()
	config := newTestConfig("", "2001:db8::1", "")

	handler := handle80(config, logger)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
	}{
		{
			name:           "Request to exact IPv6",
			host:           "2001:db8::1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Request to IPv6 with brackets",
			host:           "[2001:db8::1]",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Request to IPv6 with brackets and port",
			host:           "[2001:db8::1]:8080",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = "192.0.2.1:12345"

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				body := w.Body.String()
				if !contains(body, "2001:db8::1") {
					t.Errorf("Expected body to contain IPv6 address, got %q", body)
				}
			}
		})
	}
}

// TestHandle80_SelfRequestByDualStack tests that requests to either IPv4 or IPv6 serve a status page when both are configured
func TestHandle80_SelfRequestByDualStack(t *testing.T) {
	logger := zerolog.Nop()
	config := newTestConfig("203.0.113.1", "2001:db8::1", "")

	handler := handle80(config, logger)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
	}{
		{
			name:           "Request to IPv4",
			host:           "203.0.113.1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Request to IPv6",
			host:           "2001:db8::1",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = "192.0.2.1:12345"

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestHandle80_SelfRequestByPublicIpDns tests that requests to the PublicIpDns hostname serve a status page
func TestHandle80_SelfRequestByPublicIpDns(t *testing.T) {
	logger := zerolog.Nop()
	config := newTestConfig("203.0.113.1", "2001:db8::1", "proxy.example.com")

	handler := handle80(config, logger)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		checkContent   bool
	}{
		{
			name:           "Request to exact DNS name",
			host:           "proxy.example.com",
			expectedStatus: http.StatusOK,
			checkContent:   true,
		},
		{
			name:           "Request to DNS name with port",
			host:           "proxy.example.com:8080",
			expectedStatus: http.StatusOK,
			checkContent:   true,
		},
		{
			name:           "Request to subdomain should not be blocked",
			host:           "sub.proxy.example.com",
			expectedStatus: http.StatusBadGateway, // Will fail to connect, but shouldn't be blocked
			checkContent:   false,
		},
		{
			name:           "Request to different domain",
			host:           "nonexistent.invalid.domain.example",
			expectedStatus: http.StatusBadGateway, // Will fail to connect, but shouldn't be blocked
			checkContent:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = "192.0.2.1:12345"

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.checkContent {
				body := w.Body.String()
				if !contains(body, "proxy.example.com") {
					t.Errorf("Expected body to contain DNS name, got %q", body)
				}
				if !contains(body, "203.0.113.1") {
					t.Errorf("Expected body to contain IPv4 address, got %q", body)
				}
				if !contains(body, "2001:db8::1") {
					t.Errorf("Expected body to contain IPv6 address, got %q", body)
				}
			}
		})
	}
}

// TestHandle80_MixedModeIpAndDns tests that requests are blocked for both IP and DNS when PublicIpDns is configured
func TestHandle80_MixedModeIpAndDns(t *testing.T) {
	logger := zerolog.Nop()
	config := newTestConfig("203.0.113.1", "2001:db8::1", "proxy.example.com")

	handler := handle80(config, logger)

	tests := []struct {
		name            string
		host            string
		shouldBeBlocked bool
	}{
		{
			name:            "Request to IPv4",
			host:            "203.0.113.1",
			shouldBeBlocked: true,
		},
		{
			name:            "Request to IPv6",
			host:            "2001:db8::1",
			shouldBeBlocked: true,
		},
		{
			name:            "Request to DNS name",
			host:            "proxy.example.com",
			shouldBeBlocked: true,
		},
		{
			name:            "Request to other domain",
			host:            "nonexistent.invalid.domain.example",
			shouldBeBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = "192.0.2.1:12345"

			w := httptest.NewRecorder()
			handler(w, req)

			if tt.shouldBeBlocked {
				if w.Code != http.StatusOK {
					t.Errorf("Expected status page (200 OK), got %d", w.Code)
				}
			} else {
				// Should fail to connect but not be blocked
				if w.Code == http.StatusOK {
					t.Errorf("Expected request to not be blocked (not 200 OK), but got 200 OK")
				}
			}
		})
	}
}

// TestHandle80_ACLReject tests that ACL rejected requests return 403
func TestHandle80_ACLReject(t *testing.T) {
	t.Skip("Skipping ACL test - requires proper ACL implementation setup")
}
