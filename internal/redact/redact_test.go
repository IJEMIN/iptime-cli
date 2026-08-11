package redact

import "testing"

func TestSecretsRedactsNestedValues(t *testing.T) {
	input := map[string]any{
		"ssid":     "ExampleWiFi",
		"password": "not-a-real-password",
		"radius":   map[string]any{"secret": "synthetic-secret", "server": "192.0.2.20"},
		"items":    []any{map[string]any{"token": "synthetic-token", "ip": "192.0.2.10"}},
	}
	result := Secrets(input).(map[string]any)
	if result["password"] != masked {
		t.Fatalf("password was not redacted: %#v", result)
	}
	if result["ssid"] != "ExampleWiFi" {
		t.Fatalf("SSID should remain functional output: %#v", result)
	}
	radius := result["radius"].(map[string]any)
	if radius["secret"] != masked || radius["server"] != "192.0.2.20" {
		t.Fatalf("unexpected nested redaction: %#v", radius)
	}
}

func TestDiagnosticAlsoRedactsNetworkIdentity(t *testing.T) {
	result := Diagnostic(map[string]any{
		"ssid":    "ExampleWiFi",
		"mac":     "02:00:00:00:00:01",
		"ip":      "192.0.2.10",
		"product": "example-router",
	}).(map[string]any)
	if result["ssid"] != masked || result["mac"] != masked || result["ip"] != masked {
		t.Fatalf("network identity was not redacted: %#v", result)
	}
	if result["product"] != "example-router" {
		t.Fatalf("product should remain: %#v", result)
	}
}

func TestContainsSecrets(t *testing.T) {
	if !ContainsSecrets(map[string]any{"nested": []any{map[string]any{"password": "synthetic"}}}) {
		t.Fatal("nested password was not detected")
	}
	if ContainsSecrets(map[string]any{"ssid": "ExampleWiFi", "ip": "192.0.2.10"}) {
		t.Fatal("ordinary network configuration was treated as a shell secret")
	}
	aliases := map[string]any{
		"admin_pw":     "synthetic",
		"access_token": "synthetic",
		"apiKey":       "synthetic",
		"passphrase":   "synthetic",
		"wpa_key":      "synthetic",
		"wpapsk":       "synthetic",
		"radiusSecret": "synthetic",
		"session_id":   "synthetic",
		"sessionId":    "synthetic",
		"wps_pin":      "synthetic",
		"api_key":      "synthetic",
		"credential":   "synthetic",
		"bearer":       "synthetic",
	}
	redacted := Secrets(aliases).(map[string]any)
	for key := range aliases {
		if redacted[key] != masked {
			t.Fatalf("alias %q was not redacted: %#v", key, redacted)
		}
	}
}

func TestSecretsRedactsTypedSlicesAndMaps(t *testing.T) {
	input := []map[string]any{{
		"method": "wireless/bss/show",
		"result": map[string]any{"password": "not-a-real-password"},
	}}
	result := Secrets(input).([]any)
	item := result[0].(map[string]any)
	nested := item["result"].(map[string]any)
	if nested["password"] != masked {
		t.Fatalf("typed slice bypassed redaction: %#v", result)
	}
}
