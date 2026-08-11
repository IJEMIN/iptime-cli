package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	pngcodec "image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyRejectsSecretsInShellArgument(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{
		"apply", "--params", `{"bss":"2g-main","password":"not-a-real-password"}`, "wireless/bss/set",
	}, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "must use --params-stdin") {
		t.Fatalf("secret shell argument was accepted; exit=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "not-a-real-password") {
		t.Fatalf("secret was echoed in error: %s", stderr.String())
	}
}

func TestApplyRejectsAllRawParamsInShellArgument(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"apply", "--params", `"Example Router"`, "system/name"}, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "must use --params-stdin") {
		t.Fatalf("raw write argument was accepted: code=%d stderr=%s", code, stderr.String())
	}
}

func TestCommandHelpIsSuccessful(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"apply", "--help"}, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 || !strings.Contains(stdout.String(), "--force-high-risk") || stderr.Len() != 0 {
		t.Fatalf("unexpected help result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestNestedCommandHelpIsSuccessful(t *testing.T) {
	for _, args := range [][]string{{"wifi", "set", "--help"}, {"port-forward", "add", "--help"}, {"credential", "delete", "--help"}} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
		if code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("unexpected help for %#v: code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestGlobalHelpIsSuccessful(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--help"}, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 || !strings.Contains(stdout.String(), "Quick") && !strings.Contains(stdout.String(), "Commands:") || stderr.Len() != 0 {
		t.Fatalf("unexpected help result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestNormalizedCaptchaPNGValidatesContent(t *testing.T) {
	input := image.NewRGBA(image.Rect(0, 0, 2, 2))
	input.Set(0, 0, color.Black)
	var encoded bytes.Buffer
	if err := pngcodec.Encode(&encoded, input); err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizedCaptchaPNG(encoded.Bytes(), "image/png")
	if err != nil {
		t.Fatalf("valid captcha rejected: %v", err)
	}
	if _, format, err := image.Decode(bytes.NewReader(normalized)); err != nil || format != "png" {
		t.Fatalf("captcha was not normalized to PNG: format=%q err=%v", format, err)
	}
	for name, test := range map[string]struct {
		raw         []byte
		contentType string
	}{
		"invalid bytes": {raw: []byte("not-an-image"), contentType: "image/png"},
		"mime mismatch": {raw: encoded.Bytes(), contentType: "image/gif"},
		"active format": {raw: []byte("<svg><script/></svg>"), contentType: "image/svg+xml"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizedCaptchaPNG(test.raw, test.contentType); err == nil {
				t.Fatal("unsafe captcha content was accepted")
			}
		})
	}
	if captchaDimensionsSafe(1<<31-1, 1<<31-1) {
		t.Fatal("overflow-sized captcha dimensions were accepted")
	}
}

func TestCommandsRejectExtraArguments(t *testing.T) {
	for _, args := range [][]string{{"version", "unexpected"}, {"status", "unexpected"}, {"clients", "unexpected"}, {"dhcp", "unexpected"}, {"credential", "delete", "--yes", "unexpected"}} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), `"kind": "usage"`) {
			t.Fatalf("extra argument accepted for %#v: code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestApplyDryRunFromStdinRedactsSecretsWithoutNetwork(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{
		"apply", "--params-stdin", "wireless/bss/set",
	}, strings.NewReader("{\"bss\":\"2g-main\",\"password\":\"not-a-real-password\"}\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "not-a-real-password") || !strings.Contains(stdout.String(), "<redacted>") {
		t.Fatalf("secret was exposed: %s", stdout.String())
	}
}

func TestParamsRejectExplicitNull(t *testing.T) {
	for _, args := range [][]string{
		{"call", "--params", "null", "system/name"},
		{"apply", "--params-stdin", "system/name"},
	} {
		stdin := strings.NewReader("")
		if args[0] == "apply" {
			stdin = strings.NewReader("null\n")
		}
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, stdin, stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), "JSON null is not a supported params value") {
			t.Fatalf("null params accepted for %#v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestKnownRawWriteRequiresParams(t *testing.T) {
	for _, args := range [][]string{
		{"apply", "wireless/bss/set"},
		{"apply", "--yes", "--force-high-risk", "wireless/bss/clear"},
	} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), "known write methods require") {
			t.Fatalf("missing write params accepted for %#v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestStatusAuthenticatesAndLogsOut(t *testing.T) {
	methods := make([]string, 0)
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		methods = append(methods, method)
		switch method {
		case "session/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "synthetic", Path: "/"})
			writeRPC(w, "done")
		case "product/info":
			writeRPC(w, map[string]any{"name": "example-router", "mac": "02:00:00:00:00:01"})
		case "system/name":
			writeRPC(w, "example-router")
		case "network/interface/lan/info":
			writeRPC(w, map[string]any{"ip": "192.0.2.1"})
		case "network/interface/wan1/info":
			writeRPC(w, map[string]any{"ip": "198.51.100.10"})
		case "network/dns/info":
			writeRPC(w, []any{"192.0.2.53"})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "status"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(strings.Join(methods, ","), "session/logout") {
		t.Fatalf("logout was not called: %#v", methods)
	}
	if strings.Contains(stdout.String(), "not-a-real-password") {
		t.Fatalf("password leaked: %s", stdout.String())
	}
}

func TestGroupedReadKeepsPartialResultsForUnsupportedRPC(t *testing.T) {
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "product/info":
			writeRPC(w, map[string]any{"name": "example-router"})
		case "system/name":
			writeRPCError(w, -32601, "SYNTHETIC_UNSUPPORTED_MESSAGE", nil)
		case "network/interface/lan/info", "network/interface/wan1/info", "network/dns/info":
			writeRPC(w, map[string]any{})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "status"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"partial": true`) || !strings.Contains(stdout.String(), `"code": -32601`) {
		t.Fatalf("unexpected partial result: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "SYNTHETIC_UNSUPPORTED_MESSAGE") {
		t.Fatalf("router message leaked: %s", stdout.String())
	}
}

func TestSingleItemReadFailsWhenItsRPCFails(t *testing.T) {
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "network/interface/lan/stations":
			writeRPCError(w, -32601, "SYNTHETIC_UNSUPPORTED_MESSAGE", nil)
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "clients"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), `"kind": "router_rpc"`) || !strings.Contains(stderr.String(), `"code": -32601`) {
		t.Fatalf("all-failed group was accepted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "SYNTHETIC_UNSUPPORTED_MESSAGE") {
		t.Fatalf("router message leaked: %s", stderr.String())
	}
}

func TestBackupWritesMode0600WithoutPrintingPayload(t *testing.T) {
	payload := syntheticBackupBytes()
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "config/backup":
			writeRPC(w, syntheticBackupBase64())
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	path := filepath.Join(t.TempDir(), "router.config")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "backup", "--output", path}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatalf("unexpected backup data %q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode is %o", info.Mode().Perm())
	}
	if strings.Contains(stdout.String(), string(payload)) {
		t.Fatalf("backup payload leaked to stdout: %s", stdout.String())
	}
}

func TestBackupRefusesExistingFileBeforeNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.config")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", "http://127.0.0.1:1", "--password-stdin", "backup", "--output", path}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("existing backup was not rejected: code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "keep" {
		t.Fatalf("existing file changed: data=%q err=%v", raw, err)
	}
}

func TestBackupRejectsImplausiblySmallPayload(t *testing.T) {
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "config/backup":
			writeRPC(w, base64.StdEncoding.EncodeToString([]byte("X")))
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	path := filepath.Join(t.TempDir(), "empty.config")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "backup", "--output", path}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "implausibly small config backup") {
		t.Fatalf("tiny backup accepted: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("empty backup file was created: %v", err)
	}
}

func TestApplyCreatesAutomaticLocalBackupBeforeWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	methods := make([]string, 0)
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		methods = append(methods, method)
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "config/backup":
			writeRPC(w, syntheticBackupBase64())
		case "system/name":
			writeRPC(w, "Example Router")
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "apply", "--params-stdin", "--yes", "system/name"}, strings.NewReader("\"Example Router\"\nnot-a-real-admin-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if strings.Join(methods, ",") != "session/login,config/backup,system/name,session/logout" {
		t.Fatalf("unexpected call order: %#v", methods)
	}
	paths, err := filepath.Glob(filepath.Join(home, "Library", "Application Support", "iptime-cli", "backups", "*", "*.config"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("automatic backup not found: paths=%#v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil || !bytes.Equal(raw, syntheticBackupBytes()) {
		t.Fatalf("unexpected automatic backup: data=%q err=%v", raw, err)
	}
	info, err := os.Stat(paths[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("automatic backup mode: info=%v err=%v", info, err)
	}
	if strings.Contains(stdout.String(), home) || !strings.Contains(stdout.String(), `"backup_file": "~/Library/Application Support/iptime-cli/backups/`) {
		t.Fatalf("backup path was not home-redacted: %s", stdout.String())
	}
}

func TestAutomaticBackupSanityFailureStopsWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var wrote bool
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "config/backup":
			writeRPC(w, base64.StdEncoding.EncodeToString([]byte("X")))
		case "system/name":
			wrote = true
			writeRPC(w, "Example Router")
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "apply", "--params-stdin", "--yes", "system/name"}, strings.NewReader("\"Example Router\"\nnot-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || wrote || !strings.Contains(stderr.String(), "implausibly small config backup") {
		t.Fatalf("write was not stopped: code=%d wrote=%v stderr=%s", code, wrote, stderr.String())
	}
	paths, err := filepath.Glob(filepath.Join(home, "Library", "Application Support", "iptime-cli", "backups", "*", "*.config"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("tiny automatic backup was saved: paths=%#v err=%v", paths, err)
	}
}

func TestWiFiSetPreservesFieldsAndVerifies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	state := syntheticBSS()
	state["output_only"] = "must-not-be-sent"
	state["radius"].(map[string]any)["runtime_status"] = "must-not-be-sent"
	var setParams map[string]any
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "wireless/bss/show":
			writeRPC(w, []any{state})
		case "config/backup":
			writeRPC(w, syntheticBackupBase64())
		case "wireless/bss/set":
			setParams = params.(map[string]any)
			state = syntheticBSS()
			state["ssid"] = "NewExampleWiFi"
			writeRPC(w, true)
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "wifi", "set", "--bss", "2g-main", "--ssid", "NewExampleWiFi", "--yes"}, strings.NewReader("not-a-real-admin-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if setParams["ssid"] != "NewExampleWiFi" || setParams["maxsta"] != float64(16) || setParams["commit"] != true || len(setParams) != 12 {
		t.Fatalf("unexpected set params: %#v", setParams)
	}
	if _, ok := setParams["output_only"]; ok {
		t.Fatalf("output-only field was sent: %#v", setParams)
	}
	if radius := setParams["radius"].(map[string]any); len(radius) != 4 {
		t.Fatalf("output-only radius field was sent: %#v", radius)
	}
	if strings.Contains(stdout.String(), "not-a-real-existing-password") || !strings.Contains(stdout.String(), "<redacted>") {
		t.Fatalf("password was exposed: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "not-a-real-radius-secret") {
		t.Fatalf("RADIUS secret was exposed: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"matched": true`) {
		t.Fatalf("verification result missing: %s", stdout.String())
	}
}

func TestWiFiSetFailsClosedWhenShowOmitsSerializerField(t *testing.T) {
	var wrote bool
	state := syntheticBSS()
	delete(state, "password")
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "wireless/bss/show":
			writeRPC(w, []any{state})
		case "wireless/bss/set":
			wrote = true
			writeRPC(w, true)
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "wifi", "set", "--bss", "2g-main", "--ssid", "NewExampleWiFi", "--yes", "--no-backup"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), `omitted required field \"password\"`) || wrote {
		t.Fatalf("incomplete BSS was not rejected: code=%d wrote=%v stderr=%s", code, wrote, stderr.String())
	}
}

func TestBSSSchemaRejectsUnsafePreservedValues(t *testing.T) {
	tests := map[string]func(map[string]any){
		"null password":     func(value map[string]any) { value["password"] = nil },
		"empty password":    func(value map[string]any) { value["password"] = "" },
		"object password":   func(value map[string]any) { value["password"] = map[string]any{"masked": true} },
		"string enable":     func(value map[string]any) { value["enable"] = "yes" },
		"string radius":     func(value map[string]any) { value["radius"] = "not-an-object" },
		"string maxsta":     func(value map[string]any) { value["maxsta"] = "sixteen" },
		"string band":       func(value map[string]any) { value["band"] = "2g" },
		"numeric channel":   func(value map[string]any) { value["channel"] = 6 },
		"empty active SSID": func(value map[string]any) { value["ssid"] = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := syntheticBSS()
			mutate(value)
			if _, err := bssSetParams(value, false); err == nil {
				t.Fatalf("unsafe BSS value was accepted: %#v", value)
			}
		})
	}
}

func TestWiFiRejectsUnknownAuthModeBeforeNetwork(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"wifi", "set", "--bss", "2g-main", "--authenc", "typo-open-mode"}, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "--authenc is not one of the modes") {
		t.Fatalf("unknown auth mode accepted: code=%d stderr=%s", code, stderr.String())
	}
}

func TestBSSSchemaAllowsExplicitPasswordReplacement(t *testing.T) {
	value := syntheticBSS()
	value["password"] = map[string]any{"masked": true}
	selected, err := bssSetParams(value, true)
	if err != nil {
		t.Fatalf("replacement path rejected masked current password: %v", err)
	}
	selected["password"] = "not-a-real-new-password"
	if err := validateBSSSetParams(selected, false); err != nil {
		t.Fatalf("replacement password did not produce a valid request: %v", err)
	}
}

func TestWiFiVerificationRejectsCollateralMutation(t *testing.T) {
	state := syntheticBSS()
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "wireless/bss/show":
			writeRPC(w, []any{state})
		case "wireless/bss/set":
			state = syntheticBSS()
			state["ssid"] = "NewExampleWiFi"
			state["authenc"] = "open_none"
			state["password"] = ""
			writeRPC(w, true)
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "wifi", "set", "--bss", "2g-main", "--ssid", "NewExampleWiFi", "--yes", "--no-backup"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "verification did not match field") {
		t.Fatalf("collateral mutation was accepted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestWiFiDisableUsesMinimalObservedSchema(t *testing.T) {
	state := syntheticBSS()
	var request map[string]any
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "wireless/bss/show":
			writeRPC(w, []any{state})
		case "wireless/bss/set":
			request = params.(map[string]any)
			state = syntheticBSS()
			state["enable"] = false
			writeRPC(w, true)
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "wifi", "set", "--bss", "2g-main", "--enable=false", "--yes", "--no-backup"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if len(request) != 3 || request["bss"] != "2g-main" || request["enable"] != false || request["commit"] != true {
		t.Fatalf("unexpected disable request: %#v", request)
	}
}

func TestPortForwardAddUsesExpectedSchemaAndVerifies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var request map[string]any
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "portforward/add":
			request = params.(map[string]any)
			writeRPC(w, true)
		case "config/backup":
			writeRPC(w, syntheticBackupBase64())
		case "portforward/get":
			writeRPC(w, []any{map[string]any{
				"name": "example-web", "active": true, "protocol": "tcpudp",
				"target": "192.168.0.10", "src": map[string]any{"start": 8443},
				"dst": map[string]any{"start": 443}, "priority": 0,
			}})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{
		"--router", server.URL, "--password-stdin", "port-forward", "add",
		"--name", "example-web", "--target", "192.168.0.10", "--protocol", "tcpudp",
		"--external-port", "8443", "--internal-port", "443", "--yes",
	}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if request["name"] != "example-web" || request["target"] != "192.168.0.10" || request["protocol"] != "tcpudp" || request["active"] != true || len(request) != 6 {
		t.Fatalf("unexpected request: %#v", request)
	}
	if !strings.Contains(stdout.String(), `"matched": true`) {
		t.Fatalf("verification result missing: %s", stdout.String())
	}
}

func TestPortForwardRejectsInvalidTargetAndPriorityBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"port-forward", "add", "--name", "example", "--target", "::ffff:192.168.0.10", "--external-port", "80", "--internal-port", "80"},
		{"port-forward", "add", "--name", "example", "--target", "192.168.0.10", "--external-port", "80", "--internal-port", "80", "--priority", "-1"},
	} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), `"kind": "usage"`) {
			t.Fatalf("invalid port-forward input accepted for %#v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestPortForwardDeleteUsesExpectedSchemaAndVerifiesAbsence(t *testing.T) {
	var request map[string]any
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "portforward/del":
			request = params.(map[string]any)
			writeRPC(w, true)
		case "portforward/get":
			writeRPC(w, []any{map[string]any{"name": "other-rule"}})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "port-forward", "delete", "--name", "example-web", "--yes", "--no-backup"}, strings.NewReader("not-a-real-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	list, ok := request["list"].([]any)
	if request["type"] != "user" || !ok || len(list) != 1 || list[0] != "example-web" {
		t.Fatalf("unexpected delete request: %#v", request)
	}
	if !strings.Contains(stdout.String(), `"matched": true`) {
		t.Fatalf("delete verification missing: %s", stdout.String())
	}
}

func TestVerificationDoesNotCoerceStringsToNumbersOrBooleans(t *testing.T) {
	for _, test := range []struct {
		expected any
		actual   any
		want     bool
	}{
		{expected: true, actual: "true", want: false},
		{expected: 8443, actual: "8443", want: false},
		{expected: 8443, actual: json.Number("8443"), want: true},
		{expected: json.Number("1.0"), actual: json.Number("1"), want: true},
		{expected: "tcp", actual: "tcp", want: true},
		{expected: []string{"1"}, actual: []any{json.Number("1")}, want: false},
	} {
		if got := valueMatches(test.expected, test.actual); got != test.want {
			t.Fatalf("valueMatches(%#v, %#v)=%v want %v", test.expected, test.actual, got, test.want)
		}
	}
}

func TestWiFiShowRedactsTypedResults(t *testing.T) {
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "wireless/info", "wireless/band/show":
			writeRPC(w, []any{})
		case "wireless/bss/show":
			writeRPC(w, []any{map[string]any{
				"bss": "2g-main", "ssid": "ExampleWiFi", "password": "not-a-real-wifi-password",
				"radius": map[string]any{"secret": "not-a-real-radius-secret"},
			}})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "wifi", "show"}, strings.NewReader("not-a-real-admin-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	for _, marker := range []string{"not-a-real-admin-password", "not-a-real-wifi-password", "not-a-real-radius-secret"} {
		if strings.Contains(stdout.String(), marker) {
			t.Fatalf("secret %q was exposed: %s", marker, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "<redacted>") {
		t.Fatalf("redaction marker missing: %s", stdout.String())
	}
}

func TestRouterErrorDoesNotExposeRouterControlledText(t *testing.T) {
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		if method != "session/login" {
			t.Fatalf("unexpected method %q", method)
		}
		writeRPCError(w, -32001, "SYNTHETIC_ROUTER_MESSAGE_SECRET", map[string]any{"detail": "SYNTHETIC_ROUTER_DATA_SECRET"})
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "status"}, strings.NewReader("not-a-real-admin-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), `"kind": "router_rpc"`) || !strings.Contains(stderr.String(), `"code": -32001`) {
		t.Fatalf("unexpected error: code=%d stderr=%s", code, stderr.String())
	}
	for _, marker := range []string{"not-a-real-admin-password", "SYNTHETIC_ROUTER_MESSAGE_SECRET", "SYNTHETIC_ROUTER_DATA_SECRET"} {
		if strings.Contains(stderr.String(), marker) {
			t.Fatalf("router-controlled text %q leaked: %s", marker, stderr.String())
		}
	}
}

func TestWriteFailureReportsRedactedAutomaticBackupPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	server := syntheticRouter(t, func(method string, params any, w http.ResponseWriter) {
		switch method {
		case "session/login":
			writeRPC(w, "done")
		case "config/backup":
			writeRPC(w, syntheticBackupBase64())
		case "system/name":
			writeRPCError(w, -32002, "SYNTHETIC_WRITE_SECRET", map[string]any{"detail": "SYNTHETIC_DATA_SECRET"})
		case "session/logout":
			writeRPC(w, true)
		default:
			t.Fatalf("unexpected method %q", method)
		}
	})
	defer server.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute([]string{"--router", server.URL, "--password-stdin", "apply", "--params-stdin", "--yes", "system/name"}, strings.NewReader("\"Example Router\"\nnot-a-real-admin-password\n"), stdout, stderr, BuildInfo{Version: "test"})
	if code == 0 || !strings.Contains(stderr.String(), "after local backup was saved at ~/Library/Application Support/iptime-cli/backups/") {
		t.Fatalf("backup recovery path missing: code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), home) || strings.Contains(stderr.String(), "SYNTHETIC_WRITE_SECRET") || strings.Contains(stderr.String(), "SYNTHETIC_DATA_SECRET") {
		t.Fatalf("sensitive error data leaked: %s", stderr.String())
	}
}

func TestSafetyGatesRunBeforeNetwork(t *testing.T) {
	tests := [][]string{
		{"call", "config/backup"},
		{"apply", "--yes", "network/interface/lan/config"},
		{"apply", "--yes", "future/method"},
	}
	for _, args := range tests {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, strings.NewReader(""), stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), "safety") {
			t.Fatalf("gate failed for %#v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestBlockedMethodGateRunsBeforeReadingParams(t *testing.T) {
	for _, args := range [][]string{
		{"apply", "--params-stdin", "config/reset"},
		{"call", "--params-stdin", "config/reset"},
	} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(args, failReader{t: t}, stdout, stderr, BuildInfo{Version: "test"})
		if code == 0 || !strings.Contains(stderr.String(), `"kind": "safety"`) {
			t.Fatalf("gate failed for %#v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func syntheticRouter(t *testing.T, handler func(method string, params any, w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi/service.cgi" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		handler(fmt.Sprint(request["method"]), request["params"], w)
	}))
}

func writeRPC(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": result, "error": nil})
}

func writeRPCError(w http.ResponseWriter, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"result": nil,
		"error":  map[string]any{"code": code, "message": message, "data": data},
	})
}

func syntheticBackupBytes() []byte {
	return bytes.Repeat([]byte("synthetic-backup-payload\n"), 16)
}

func syntheticBackupBase64() string {
	return base64.StdEncoding.EncodeToString(syntheticBackupBytes())
}

func syntheticBSS() map[string]any {
	return map[string]any{
		"bss":      "2g-main",
		"band":     []any{"2g"},
		"ssid":     "OldExampleWiFi",
		"password": "not-a-real-existing-password",
		"authenc":  "wpa2psk_aes",
		"enable":   true,
		"hide":     false,
		"channel":  "6",
		"radius": map[string]any{
			"server": "192.0.2.20", "port": 1812,
			"enable_port": false, "secret": "not-a-real-radius-secret",
		},
		"access": "allow",
		"maxsta": 16,
	}
}

type failReader struct {
	t *testing.T
}

func (reader failReader) Read([]byte) (int, error) {
	reader.t.Fatal("stdin was read before the safety gate")
	return 0, io.EOF
}
