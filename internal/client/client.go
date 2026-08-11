package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	rpcPath       = "/cgi/service.cgi"
	maxRPCBody    = 8 << 20
	maxDownload   = 2 << 20
	defaultRouter = "http://192.168.0.1"
)

var (
	productPattern = regexp.MustCompile(`PRODUCT:\s*["']([^"']+)["']`)
	uiPattern      = regexp.MustCompile(`flutter_bootstrap\.js\?v=([0-9A-Za-z._-]+)`)
)

// Options configures a router connection. Public hosts are rejected by default
// so credentials cannot be sent outside a local network by mistake.
type Options struct {
	Router          string
	Interface       string
	SourceAddress   string
	Timeout         time.Duration
	AllowPublicHost bool
	InsecureTLS     bool
	UserAgent       string
}

// Client speaks the private JSON-RPC-like protocol used by the router UI.
type Client struct {
	base       *url.URL
	httpClient *http.Client
	userAgent  string
}

// RPCError is an application error returned inside an HTTP 200 response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	// Router-provided messages are intentionally not returned here. A hostile or
	// buggy device could echo credentials or request values into its error text.
	return fmt.Sprintf("router RPC error %d", e.Code)
}

// HTTPError is returned when the router does not return HTTP 200.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("router returned HTTP status %d", e.StatusCode)
}

// ProbeResult describes only public UI bootstrap metadata and requires no login.
type ProbeResult struct {
	Product        string `json:"product,omitempty"`
	UIAssetVersion string `json:"ui_asset_version,omitempty"`
}

func New(ctx context.Context, opts Options) (*Client, error) {
	base, err := normalizeRouter(opts.Router)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	resolveCtx, cancelResolve := context.WithTimeout(ctx, timeout)
	resolved, err := resolvePrivateTarget(resolveCtx, base.Hostname(), opts.AllowPublicHost)
	cancelResolve()
	if err != nil {
		return nil, err
	}

	localAddr, err := resolveLocalAddress(opts.Interface, opts.SourceAddress)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout, LocalAddr: localAddr}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        2,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: opts.InsecureTLS, // Explicit opt-in for router self-signed certificates.
		},
	}
	transport.DialContext = pinnedDialer(dialer, base.Hostname(), resolved)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = "iptime-cli/development"
	}

	return &Client{
		base: base,
		httpClient: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("router redirects are disabled")
			},
		},
		userAgent: userAgent,
	}, nil
}

// NormalizeRouterOrigin canonicalizes a router address without resolving or
// contacting it. Local credential management uses this stable origin as its
// Keychain identity even when the router is offline.
func NormalizeRouterOrigin(raw string) (string, error) {
	base, err := normalizeRouter(raw)
	if err != nil {
		return "", err
	}
	return base.String(), nil
}

func normalizeRouter(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultRouter
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse router URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("router URL must use http or https")
	}
	if u.User != nil {
		return nil, errors.New("credentials are not allowed in the router URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("router URL has no host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("router URL must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("router URL must not contain a path")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return nil, errors.New("router URL has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

func resolvePrivateTarget(ctx context.Context, host string, allowPublic bool) ([]net.IP, error) {
	var ips []net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []net.IP{parsed}
	} else {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve router host: %w", err)
		}
		for _, item := range resolved {
			ips = append(ips, item.IP)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("router host resolved to no addresses")
	}
	if !allowPublic {
		for _, ip := range ips {
			if !isLocalAddress(ip) {
				return nil, fmt.Errorf("refusing public router address %s; use --allow-public-host only when intentional", ip)
			}
		}
	}
	return ips, nil
}

func isLocalAddress(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func resolveLocalAddress(interfaceName, source string) (*net.TCPAddr, error) {
	if interfaceName != "" && source != "" {
		return nil, errors.New("use only one of --interface and --source-address")
	}
	if source != "" {
		ip := net.ParseIP(source)
		if ip == nil {
			return nil, fmt.Errorf("invalid source address %q", source)
		}
		return &net.TCPAddr{IP: ip}, nil
	}
	if interfaceName == "" {
		return nil, nil
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find interface %q: %w", interfaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read interface %q addresses: %w", interfaceName, err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil {
			return &net.TCPAddr{IP: ip}, nil
		}
	}
	return nil, fmt.Errorf("interface %q has no IPv4 address", interfaceName)
}

func pinnedDialer(dialer *net.Dialer, expectedHost string, ips []net.IP) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse dial address: %w", err)
		}
		if !strings.EqualFold(strings.Trim(host, "[]"), strings.Trim(expectedHost, "[]")) {
			return nil, fmt.Errorf("refusing unexpected dial host %q", host)
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("connect to router: %w", lastErr)
	}
}

func (c *Client) RouterOrigin() string {
	return c.base.String()
}

func (c *Client) RPC(ctx context.Context, method string, params any) (any, error) {
	payload := map[string]any{"method": method}
	if params != nil {
		payload["params"] = params
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode RPC request: %w", err)
	}

	raw, _, err := c.do(ctx, http.MethodPost, rpcPath, bytes.NewReader(body), maxRPCBody, map[string]string{
		"Content-Type":  "application/json; charset=utf-8",
		"Cache-Control": "no-store",
		"Origin":        c.base.String(),
		"Referer":       c.base.String() + "/",
	})
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode RPC envelope: %w", err)
	}
	if envelope.Error != nil {
		var data any
		if len(envelope.Error.Data) > 0 && string(envelope.Error.Data) != "null" {
			decoder := json.NewDecoder(bytes.NewReader(envelope.Error.Data))
			decoder.UseNumber()
			_ = decoder.Decode(&data)
		}
		return nil, &RPCError{Code: envelope.Error.Code, Message: envelope.Error.Message, Data: data}
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil, nil
	}
	var result any
	decoder := json.NewDecoder(bytes.NewReader(envelope.Result))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode RPC result: %w", err)
	}
	return result, nil
}

func (c *Client) Login(ctx context.Context, username, password string, captcha any) error {
	params := map[string]any{"id": username, "pw": password}
	if captcha != nil {
		params["captcha"] = captcha
	}
	result, err := c.RPC(ctx, "session/login", params)
	if err != nil {
		return err
	}
	if result != "done" {
		return errors.New("router returned an unexpected login result")
	}
	return nil
}

func (c *Client) Logout(ctx context.Context) error {
	_, err := c.RPC(ctx, "session/logout", nil)
	return err
}

func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/", nil, 256<<10, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	result := ProbeResult{}
	if match := productPattern.FindSubmatch(body); len(match) == 2 {
		result.Product = string(match[1])
	}
	if match := uiPattern.FindSubmatch(body); len(match) == 2 {
		result.UIAssetVersion = string(match[1])
	}
	return result, nil
}

func (c *Client) Download(ctx context.Context, path string) ([]byte, string, error) {
	body, header, err := c.do(ctx, http.MethodGet, path, nil, maxDownload, nil)
	if err != nil {
		return nil, "", err
	}
	return body, header.Get("Content-Type"), nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, maxBytes int64, headers map[string]string) ([]byte, http.Header, error) {
	reference, err := url.Parse(path)
	if err != nil {
		return nil, nil, fmt.Errorf("parse request path: %w", err)
	}
	if reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(reference.Path, "/") {
		return nil, nil, errors.New("request path must be an absolute path on the router")
	}
	target := c.base.ResolveReference(reference)
	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.1")
	req.Header.Set("Connection", "close")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, errors.New("router request timed out")
		}
		return nil, nil, errors.New("router network request failed")
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("read router response: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, nil, fmt.Errorf("router response exceeds %d bytes", maxBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, &HTTPError{StatusCode: resp.StatusCode}
	}
	return raw, resp.Header, nil
}
