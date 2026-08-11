package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	pngcodec "image/png"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/IJEMIN/iptime-cli/internal/client"
	"github.com/IJEMIN/iptime-cli/internal/credential"
	"github.com/IJEMIN/iptime-cli/internal/redact"
	"golang.org/x/term"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Build  BuildInfo

	lines    *bufio.Reader
	cfg      globalOptions
	openFile func(string) error
}

type globalOptions struct {
	router          string
	interfaceName   string
	sourceAddress   string
	timeout         time.Duration
	username        string
	passwordStdin   bool
	noKeychain      bool
	captcha         bool
	allowPublicHost bool
	insecureTLS     bool
	showSecrets     bool
	compact         bool
}

type cliError struct {
	Kind    string
	Message string
	Code    int
	Data    any
}

func (e *cliError) Error() string { return e.Message }

func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer, build BuildInfo) int {
	app := &App{
		Stdin: stdin, Stdout: stdout, Stderr: stderr, Build: build,
		lines: bufio.NewReader(stdin),
		openFile: func(path string) error {
			return exec.Command("/usr/bin/open", path).Run()
		},
	}
	if err := app.run(args); err != nil {
		app.writeError(err)
		return 1
	}
	return 0
}

func (a *App) run(args []string) error {
	global := flag.NewFlagSet("iptime", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	var help bool
	defaultRouter := envOr("IPTIME_ROUTER", "http://192.168.0.1")
	global.StringVar(&a.cfg.router, "router", defaultRouter, "router URL or address")
	global.StringVar(&a.cfg.interfaceName, "interface", envOr("IPTIME_INTERFACE", ""), "macOS network interface to bind")
	global.StringVar(&a.cfg.sourceAddress, "source-address", "", "local IPv4 source address")
	global.DurationVar(&a.cfg.timeout, "timeout", 8*time.Second, "request timeout")
	global.StringVar(&a.cfg.username, "username", envOr("IPTIME_USERNAME", "admin"), "router login name")
	global.BoolVar(&a.cfg.passwordStdin, "password-stdin", false, "read router password from one stdin line")
	global.BoolVar(&a.cfg.noKeychain, "no-keychain", false, "do not read the router password from Keychain")
	global.BoolVar(&a.cfg.captcha, "captcha", false, "open and prompt for a router captcha before login")
	global.BoolVar(&a.cfg.allowPublicHost, "allow-public-host", false, "allow sending credentials to a public address")
	global.BoolVar(&a.cfg.insecureTLS, "insecure", false, "accept a self-signed HTTPS certificate")
	global.BoolVar(&a.cfg.showSecrets, "show-secrets", false, "include passwords and secrets in command output")
	global.BoolVar(&a.cfg.compact, "compact", false, "emit compact JSON")
	global.BoolVar(&help, "help", false, "show help")
	global.BoolVar(&help, "h", false, "show help")

	if err := global.Parse(args); err != nil {
		return usageError(err.Error())
	}
	if a.cfg.timeout <= 0 {
		return usageError("--timeout must be greater than zero")
	}
	if help {
		a.printUsage()
		return nil
	}
	rest := global.Args()
	if len(rest) == 0 {
		a.printUsage()
		return nil
	}
	command, commandArgs := rest[0], rest[1:]
	if len(commandArgs) == 1 && (commandArgs[0] == "--help" || commandArgs[0] == "-h") {
		a.printCommandUsage(command)
		return nil
	}
	switch command {
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "version":
		if len(commandArgs) != 0 {
			return usageError("version takes no arguments")
		}
		return a.writeSuccess("version", map[string]any{"version": a.Build.Version, "commit": a.Build.Commit, "date": a.Build.Date})
	case "probe":
		return a.runProbe(commandArgs)
	case "doctor":
		return a.runDoctor(commandArgs)
	case "credential":
		return a.runCredential(commandArgs)
	case "login":
		return a.runLogin(commandArgs)
	case "status":
		if len(commandArgs) != 0 {
			return usageError("status takes no arguments")
		}
		return a.runReadGroup("status", statusMethods())
	case "clients":
		if len(commandArgs) != 0 {
			return usageError("clients takes no arguments")
		}
		return a.runReadGroup("clients", []methodCall{{Method: "network/interface/lan/stations"}})
	case "dhcp":
		if len(commandArgs) != 0 {
			return usageError("dhcp takes no arguments")
		}
		return a.runReadGroup("dhcp", dhcpMethods())
	case "wifi":
		return a.runWiFi(commandArgs)
	case "port-forward":
		return a.runPortForward(commandArgs)
	case "call":
		return a.runCall(commandArgs)
	case "apply":
		return a.runApply(commandArgs)
	case "backup":
		return a.runBackup(commandArgs)
	default:
		return usageError("unknown command " + command)
	}
}

func (a *App) newClient(ctx context.Context) (*client.Client, error) {
	return client.New(ctx, client.Options{
		Router:          a.cfg.router,
		Interface:       a.cfg.interfaceName,
		SourceAddress:   a.cfg.sourceAddress,
		Timeout:         a.cfg.timeout,
		AllowPublicHost: a.cfg.allowPublicHost,
		InsecureTLS:     a.cfg.insecureTLS,
		UserAgent:       "iptime-cli/" + a.Build.Version,
	})
}

func (a *App) withAuth(ctx context.Context, fn func(*client.Client) (any, error)) (any, error) {
	router, err := a.newClient(ctx)
	if err != nil {
		return nil, err
	}
	password, err := a.routerPassword(router.RouterOrigin())
	if err != nil {
		return nil, err
	}
	var captcha any
	var cleanup func()
	if a.cfg.captcha {
		captcha, cleanup, err = a.prepareCaptcha(ctx, router)
		if err != nil {
			return nil, err
		}
		defer cleanup()
	}
	if err := router.Login(ctx, a.cfg.username, password, captcha); err != nil {
		return nil, withCaptchaHint(err)
	}
	password = ""
	defer func() {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = router.Logout(logoutCtx)
	}()
	return fn(router)
}

func (a *App) routerPassword(routerOrigin string) (string, error) {
	if a.cfg.passwordStdin {
		password, err := a.readLine()
		if err != nil {
			return "", fmt.Errorf("read router password: %w", err)
		}
		return password, nil
	}
	if !a.cfg.noKeychain {
		password, err := credential.New(routerOrigin).Get(a.cfg.username)
		if err == nil {
			return password, nil
		}
		if !errors.Is(err, credential.ErrNotFound) {
			return "", err
		}
	}
	return a.readSecret("Router password: ")
}

func (a *App) readSecret(prompt string) (string, error) {
	file, ok := a.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("no password available; run 'iptime credential set' or use --password-stdin")
	}
	_, _ = fmt.Fprint(a.Stderr, prompt)
	raw, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(a.Stderr)
	if err != nil {
		return "", fmt.Errorf("read hidden password: %w", err)
	}
	return string(raw), nil
}

func (a *App) readLine() (string, error) {
	line, err := a.lines.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" && errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	return line, nil
}

func (a *App) prepareCaptcha(ctx context.Context, router *client.Client) (any, func(), error) {
	result, err := router.RPC(ctx, "captcha/new", nil)
	if err != nil {
		return nil, func() {}, err
	}
	path, ok := result.(string)
	if !ok || !strings.HasPrefix(path, "/captcha/") {
		return nil, func() {}, errors.New("router returned an invalid captcha path")
	}
	raw, contentType, err := router.Download(ctx, path)
	if err != nil {
		return nil, func() {}, err
	}
	pngImage, err := normalizedCaptchaPNG(raw, contentType)
	if err != nil {
		return nil, func() {}, err
	}
	file, err := os.CreateTemp("", "iptime-captcha-*.png")
	if err != nil {
		return nil, func() {}, fmt.Errorf("create captcha file: %w", err)
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return nil, func() {}, err
	}
	if _, err := file.Write(pngImage); err != nil {
		_ = file.Close()
		cleanup()
		return nil, func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if a.openFile == nil {
		a.openFile = func(path string) error { return exec.Command("/usr/bin/open", path).Run() }
	}
	if err := a.openFile(name); err != nil {
		cleanup()
		return nil, func() {}, errors.New("could not open the captcha image")
	}
	_, _ = fmt.Fprint(a.Stderr, "Captcha image opened.\nCaptcha: ")
	code, err := a.readLine()
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("read captcha: %w", err)
	}
	return map[string]any{"text": code, "url": path}, cleanup, nil
}

func normalizedCaptchaPNG(raw []byte, contentType string) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, errors.New("router returned an invalid captcha content type")
	}
	wantFormat, ok := map[string]string{
		"image/gif":  "gif",
		"image/jpeg": "jpeg",
		"image/png":  "png",
	}[strings.ToLower(mediaType)]
	if !ok {
		return nil, errors.New("router returned an unsupported captcha image type")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != wantFormat || !captchaDimensionsSafe(config.Width, config.Height) {
		return nil, errors.New("router returned an invalid captcha image")
	}
	decoded, format, err := image.Decode(bytes.NewReader(raw))
	if err != nil || format != wantFormat {
		return nil, errors.New("router returned an invalid captcha image")
	}
	var output bytes.Buffer
	if err := pngcodec.Encode(&output, decoded); err != nil {
		return nil, errors.New("could not normalize the captcha image")
	}
	return output.Bytes(), nil
}

func captchaDimensionsSafe(width, height int) bool {
	const maxPixels = 4 << 20
	return width > 0 && height > 0 && width <= maxPixels && height <= maxPixels/width
}

func (a *App) writeSuccess(command string, data any) error {
	if !a.cfg.showSecrets {
		data = redact.Secrets(data)
	}
	envelope := map[string]any{"ok": true, "command": command, "data": data}
	encoder := json.NewEncoder(a.Stdout)
	encoder.SetEscapeHTML(false)
	if !a.cfg.compact {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(envelope)
}

func (a *App) writeError(err error) {
	item := &cliError{Kind: "error", Message: err.Error()}
	var typed *cliError
	if errors.As(err, &typed) {
		item = typed
	}
	var rpcErr *client.RPCError
	if errors.As(err, &rpcErr) {
		item.Kind = "router_rpc"
		item.Code = rpcErr.Code
	}
	envelope := map[string]any{
		"ok": false,
		"error": map[string]any{
			"kind":    item.Kind,
			"message": item.Message,
		},
	}
	if item.Code != 0 {
		envelope["error"].(map[string]any)["code"] = item.Code
	}
	encoder := json.NewEncoder(a.Stderr)
	encoder.SetEscapeHTML(false)
	if !a.cfg.compact {
		encoder.SetIndent("", "  ")
	}
	_ = encoder.Encode(envelope)
}

func (a *App) printUsage() {
	_, _ = fmt.Fprint(a.Stdout, `iptime - macOS CLI for ipTIME routers

Usage:
  iptime [global options] <command> [command options]

Commands:
  probe                 Inspect the public router UI bootstrap
  doctor                Produce a privacy-redacted diagnostic summary
  credential set        Store a password through macOS Keychain's prompt
  credential status     Check whether a Keychain item exists
  credential delete     Delete a Keychain item (requires --yes)
  login                 Verify authentication
  status                Read product and network status
  clients               List connected LAN stations
  dhcp                  Read DHCP configuration, state, and leases
  wifi [show|set]       Read or safely update one Wi-Fi BSS
  port-forward [...]    List, add, or delete port-forward rules
  call                  Call a classified read-only RPC method
  apply                 Dry-run or call a state-changing RPC method
  backup                Save a sensitive router config backup with mode 0600
  version               Print build information

Global options must appear before the command. Important options:
  --router <url>        Default: http://192.168.0.1
  --interface <name>    Bind traffic to a macOS interface
  --username <name>     Default: admin
  --password-stdin      Read one password line without using Keychain
  --captcha             Open and prompt for a router captcha
  --insecure            Accept a self-signed HTTPS certificate (dangerous)
  --show-secrets        Disable output secret redaction
  --compact             Emit compact JSON

Run 'iptime <command> --help' for command details.
`)
}

func (a *App) printCommandUsage(command string) {
	usage := map[string]string{
		"probe":        "iptime [global options] probe\n",
		"doctor":       "iptime [global options] doctor\n",
		"credential":   "iptime [global options] credential <set|status|delete [--yes]>\n",
		"login":        "iptime [global options] login\n",
		"status":       "iptime [global options] status\n",
		"clients":      "iptime [global options] clients\n",
		"dhcp":         "iptime [global options] dhcp\n",
		"wifi":         "iptime [global options] wifi show\niptime [global options] wifi set --bss <id> [--ssid <name>] [--authenc <mode>] [--enable <bool>] [--hide <bool>] [--set-password|--wifi-password-stdin] [--yes]\n",
		"port-forward": "iptime [global options] port-forward list\niptime [global options] port-forward add --name <name> --target <private-ip> --external-port <port> --internal-port <port> [--protocol tcp|udp|tcpudp] [--yes]\niptime [global options] port-forward delete --name <name>... [--type user|upnp] [--yes]\n",
		"call":         "iptime [global options] call [--params <json>|--params-stdin] <read-method>\n",
		"apply":        "iptime [global options] apply [--params-stdin] [--yes] [--no-backup] [--force-high-risk|--force-unknown] <write-method>\nWith both stdin options, provide the JSON params line before the router-password line.\n",
		"backup":       "iptime [global options] backup --output <path.config>\n",
		"version":      "iptime version\n",
	}
	if text, ok := usage[command]; ok {
		_, _ = fmt.Fprint(a.Stdout, text)
		return
	}
	a.printUsage()
}

func (a *App) runProbe(args []string) error {
	if len(args) != 0 {
		return usageError("probe takes no arguments")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router, err := a.newClient(ctx)
	if err != nil {
		return err
	}
	result, err := router.Probe(ctx)
	if err != nil {
		return err
	}
	return a.writeSuccess("probe", result)
}

func (a *App) runDoctor(args []string) error {
	if len(args) != 0 {
		return usageError("doctor takes no arguments")
	}
	data := map[string]any{
		"version":          a.Build.Version,
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
		"interface_bound":  a.cfg.interfaceName != "" || a.cfg.sourceAddress != "",
		"router_reachable": false,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if router, err := a.newClient(ctx); err == nil {
		if probe, err := router.Probe(ctx); err == nil {
			data["router_reachable"] = true
			data["probe"] = probe
		}
	}
	if origin, err := client.NormalizeRouterOrigin(a.cfg.router); err == nil && !a.cfg.noKeychain {
		exists, keychainErr := credential.New(origin).Exists(a.cfg.username)
		if keychainErr == nil {
			data["keychain_credential"] = exists
		}
	}
	return a.writeSuccess("doctor", redact.Diagnostic(data))
}

func (a *App) runCredential(args []string) error {
	if len(args) == 0 {
		return usageError("credential requires set, status, or delete")
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		a.printCommandUsage("credential")
		return nil
	}
	origin, err := client.NormalizeRouterOrigin(a.cfg.router)
	if err != nil {
		return err
	}
	store := credential.New(origin)
	switch args[0] {
	case "set":
		if len(args) != 1 {
			return usageError("credential set takes no arguments")
		}
		if err := store.SetInteractive(a.cfg.username, a.Stdin, a.Stdout, a.Stderr); err != nil {
			return err
		}
		return a.writeSuccess("credential set", map[string]any{"stored": true})
	case "status":
		if len(args) != 1 {
			return usageError("credential status takes no arguments")
		}
		exists, err := store.Exists(a.cfg.username)
		if err != nil {
			return err
		}
		return a.writeSuccess("credential status", map[string]any{"stored": exists})
	case "delete":
		flags := flag.NewFlagSet("credential delete", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		yes := flags.Bool("yes", false, "confirm credential deletion")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				a.printCommandUsage("credential")
				return nil
			}
			return usageError(err.Error())
		}
		if flags.NArg() != 0 {
			return usageError("credential delete takes no positional arguments")
		}
		if !*yes {
			return usageError("credential delete requires --yes")
		}
		if err := store.Delete(a.cfg.username); err != nil {
			return err
		}
		return a.writeSuccess("credential delete", map[string]any{"deleted": true})
	default:
		return usageError("credential requires set, status, or delete")
	}
}

func (a *App) runLogin(args []string) error {
	if len(args) != 0 {
		return usageError("login takes no arguments; use global --captcha when required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		return router.RPC(ctx, "session/info", nil)
	})
	if err != nil {
		return err
	}
	return a.writeSuccess("login", map[string]any{"authenticated": true, "session": result})
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func usageError(message string) error {
	return &cliError{Kind: "usage", Message: message}
}

func withCaptchaHint(err error) error {
	var rpcErr *client.RPCError
	if errors.As(err, &rpcErr) {
		encoded, _ := json.Marshal(rpcErr.Data)
		if strings.Contains(strings.ToLower(rpcErr.Message+string(encoded)), "captcha") {
			return &cliError{Kind: "router_rpc", Message: fmt.Sprintf("router RPC error %d; retry with global --captcha", rpcErr.Code), Code: rpcErr.Code}
		}
	}
	return err
}

func safeBase(path string) string {
	return filepath.Base(filepath.Clean(path))
}
