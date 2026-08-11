package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRPCLoginKeepsCookieInMemory(t *testing.T) {
	t.Helper()
	var sawSessionCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != rpcPath {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch request["method"] {
		case "session/login":
			params := request["params"].(map[string]any)
			if params["id"] != "admin" || params["pw"] != "test-password" {
				t.Fatalf("unexpected login params: %#v", params)
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "synthetic-session", Path: "/", HttpOnly: true})
			_, _ = w.Write([]byte(`{"result":"done","error":null}`))
		case "session/info":
			cookie, err := r.Cookie("sid")
			if err == nil && cookie.Value == "synthetic-session" {
				sawSessionCookie = true
			}
			_, _ = w.Write([]byte(`{"result":{"type":"session","level":"user"},"error":null}`))
		default:
			t.Fatalf("unexpected method %#v", request["method"])
		}
	}))
	defer server.Close()

	ctx := context.Background()
	router, err := New(ctx, Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Login(ctx, "admin", "test-password", nil); err != nil {
		t.Fatal(err)
	}
	result, err := router.RPC(ctx, "session/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sawSessionCookie {
		t.Fatal("session cookie was not sent")
	}
	if result.(map[string]any)["level"] != "user" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRPCOmitsNilParamsAndPreservesScalarParams(t *testing.T) {
	t.Helper()
	requests := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		requests <- request
		_, _ = w.Write([]byte(`{"result":true,"error":null}`))
	}))
	defer server.Close()

	router, err := New(context.Background(), Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.RPC(context.Background(), "product/info", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := router.RPC(context.Background(), "dhcpd/lease/show", "lan"); err != nil {
		t.Fatal(err)
	}
	first, second := <-requests, <-requests
	if _, exists := first["params"]; exists {
		t.Fatalf("nil params were serialized: %#v", first)
	}
	if second["params"] != "lan" {
		t.Fatalf("scalar params changed: %#v", second)
	}
}

func TestRPCApplicationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":null,"error":{"code":-31998,"message":"Unauthenticated"}}`))
	}))
	defer server.Close()
	router, err := New(context.Background(), Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = router.RPC(context.Background(), "session/info", nil)
	rpcErr, ok := err.(*RPCError)
	if !ok || rpcErr.Code != -31998 {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestRejectsPublicAddressByDefault(t *testing.T) {
	_, err := New(context.Background(), Options{Router: "http://8.8.8.8", Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "refusing public router address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeRouterOriginDoesNotRequireResolution(t *testing.T) {
	origin, err := NormalizeRouterOrigin("offline-router.invalid:8080")
	if err != nil {
		t.Fatal(err)
	}
	if origin != "http://offline-router.invalid:8080" {
		t.Fatalf("unexpected origin %q", origin)
	}
}

func TestNormalizeRouterOriginCanonicalizesEquivalentOrigins(t *testing.T) {
	for raw, want := range map[string]string{
		"HTTP://ROUTER.Local.:80/": "http://router.local",
		"https://ROUTER.local:443": "https://router.local",
		"http://ROUTER.local:8080": "http://router.local:8080",
	} {
		origin, err := NormalizeRouterOrigin(raw)
		if err != nil {
			t.Fatalf("NormalizeRouterOrigin(%q): %v", raw, err)
		}
		if origin != want {
			t.Fatalf("NormalizeRouterOrigin(%q)=%q want %q", raw, origin, want)
		}
	}
}

func TestProbeParsesBootstrapOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<script>window.env={PRODUCT:"example-router"}</script><script src="flutter_bootstrap.js?v=1.2.3"></script>`))
	}))
	defer server.Close()
	router, err := New(context.Background(), Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := router.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Product != "example-router" || result.UIAssetVersion != "1.2.3" {
		t.Fatalf("unexpected probe result: %#v", result)
	}
}

func TestRedirectErrorDoesNotExposeLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?token=not-a-real-token", http.StatusFound)
	}))
	defer server.Close()
	router, err := New(context.Background(), Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = router.Probe(context.Background())
	if err == nil || strings.Contains(err.Error(), "not-a-real-token") {
		t.Fatalf("redirect location leaked in error: %v", err)
	}
}

func TestUnexpectedLoginResultDoesNotExposeResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":"SYNTHETIC_LOGIN_RESULT_SECRET","error":null}`))
	}))
	defer server.Close()
	router, err := New(context.Background(), Options{Router: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = router.Login(context.Background(), "admin", "not-a-real-password", nil)
	if err == nil || strings.Contains(err.Error(), "SYNTHETIC_LOGIN_RESULT_SECRET") {
		t.Fatalf("login result leaked in error: %v", err)
	}
}

func TestHTTPErrorDoesNotExposeReasonPhrase(t *testing.T) {
	err := (&HTTPError{StatusCode: 500}).Error()
	if !strings.Contains(err, "500") {
		t.Fatalf("unsafe HTTP error: %q", err)
	}
}
