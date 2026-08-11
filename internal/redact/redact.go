package redact

import (
	"bytes"
	"encoding/json"
	"strings"
)

const masked = "<redacted>"

var secretKeys = map[string]struct{}{
	"apikey":        {},
	"authorization": {},
	"bearer":        {},
	"captcha":       {},
	"cookie":        {},
	"credential":    {},
	"csrf":          {},
	"key":           {},
	"passwd":        {},
	"password":      {},
	"pw":            {},
	"secret":        {},
	"session":       {},
	"sessionid":     {},
	"sid":           {},
	"token":         {},
	"wpapsk":        {},
}

var diagnosticKeys = map[string]struct{}{
	"bssid":    {},
	"ddns":     {},
	"hostname": {},
	"ip":       {},
	"mac":      {},
	"name":     {},
	"oui":      {},
	"serial":   {},
	"ssid":     {},
	"target":   {},
	"uuid":     {},
}

func Secrets(value any) any {
	return walk(normalize(value), false)
}

func Diagnostic(value any) any {
	return walk(normalize(value), true)
}

// ContainsSecrets reports whether a JSON-like value contains a key that should
// not have been placed directly in a shell argument.
func ContainsSecrets(value any) bool {
	value = normalize(value)
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if isSecretKey(key) {
				return true
			}
			if ContainsSecrets(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if ContainsSecrets(item) {
				return true
			}
		}
	}
	return false
}

func normalize(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return value
	}
	return normalized
}

func walk(value any, diagnostic bool) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			lower := strings.ToLower(key)
			secret := isSecretKey(key)
			_, identifying := diagnosticKeys[lower]
			if secret || (diagnostic && identifying) {
				out[key] = masked
				continue
			}
			out[key] = walk(item, diagnostic)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = walk(item, diagnostic)
		}
		return out
	case json.RawMessage:
		var decoded any
		if json.Unmarshal(typed, &decoded) == nil {
			return walk(decoded, diagnostic)
		}
		return masked
	default:
		return value
	}
}

func isSecretKey(key string) bool {
	lower := strings.ToLower(key)
	if _, ok := secretKeys[lower]; ok {
		return true
	}
	for _, fragment := range []string{
		"password", "passwd", "passphrase", "token", "secret", "cookie",
		"captcha", "authorization", "private_key", "privatekey", "pre_shared_key",
		"presharedkey", "wpa_key", "wpakey", "wpa_psk", "wpapsk", "api_key",
		"apikey", "session_id", "sessionid", "access_key", "bearer", "credential",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	normalized := strings.NewReplacer("-", "_", ".", "_").Replace(lower)
	for _, token := range strings.Split(normalized, "_") {
		if token == "pw" || token == "psk" || token == "csrf" || token == "sid" || token == "session" || token == "pin" || token == "key" {
			return true
		}
	}
	return false
}
