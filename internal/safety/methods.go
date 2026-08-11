package safety

import "strings"

type Kind string

const (
	Read     Kind = "read"
	Write    Kind = "write"
	HighRisk Kind = "high-risk"
	Blocked  Kind = "blocked"
	Unknown  Kind = "unknown"
)

type Assessment struct {
	Kind   Kind   `json:"kind"`
	Reason string `json:"reason"`
}

var exactReads = map[string]struct{}{
	"admin/auth/info":                {},
	"api/has":                        {},
	"dhcpd/config/get":               {},
	"dhcpd/lease/show":               {},
	"dhcpd/reservedaddr/show":        {},
	"dhcpd/status":                   {},
	"network/dns/info":               {},
	"network/info":                   {},
	"network/interface/lan/info":     {},
	"network/interface/lan/stations": {},
	"network/interface/wan1/info":    {},
	"portforward/config":             {},
	"portforward/get":                {},
	"portforward/max":                {},
	"product/info":                   {},
	"product/name":                   {},
	"session/info":                   {},
	"system/info":                    {},
	"system/name":                    {},
	"system/temperature":             {},
	"wireless/band/info":             {},
	"wireless/band/show":             {},
	"wireless/band/support":          {},
	"wireless/bss/info":              {},
	"wireless/bss/show":              {},
	"wireless/channel/list":          {},
	"wireless/client/show":           {},
	"wireless/info":                  {},
	"wireless/mac/show":              {},
	"wireless/mlo/info":              {},
	"wireless/wps/info":              {},
}

var blockedMethods = map[string]string{
	"admin/account":  "credential changes require a typed command with hidden input",
	"admin/auth":     "credential changes require a typed command with hidden input",
	"command":        "arbitrary command execution is never exposed",
	"config/backup":  "backup data must use the dedicated file-only backup command",
	"config/reset":   "factory reset is not exposed in this release",
	"config/restore": "restore requires a typed file-only command and is not exposed in this release",
	"session/login":  "session lifecycle is managed internally",
	"session/logout": "session lifecycle is managed internally",
	"session/update": "session lifecycle is managed internally",
}

var blockedPrefixes = map[string]string{
	"admin/":         "credential and administrator changes require typed hidden-input commands",
	"command":        "arbitrary command execution is never exposed",
	"config/backup":  "backup data must use the dedicated file-only backup command",
	"config/reset":   "factory reset is not exposed in this release",
	"config/restore": "restore requires a typed file-only command and is not exposed in this release",
	"firmware/":      "firmware changes are not exposed in this release",
	"session/":       "session lifecycle is managed internally",
}

var exactWrites = map[string]struct{}{
	"dhcpd/config/set":       {},
	"dhcpd/reservedaddr/add": {},
	"dhcpd/reservedaddr/del": {},
	"led/config":             {},
	"portforward/add":        {},
	"portforward/del":        {},
	"portforward/set":        {},
	"time/config":            {},
	"wireless/band/set":      {},
	"wireless/bss/clear":     {},
	"wireless/bss/set":       {},
	"wireless/client/set":    {},
	"wireless/mac/add":       {},
	"wireless/mac/del":       {},
	"wireless/mac/policy":    {},
}

var dualMethods = map[string]struct{}{
	"portforward/config": {},
	"system/name":        {},
}

var highRiskPrefixes = []string{
	"cert/",
	"https/cert/",
	"network/dns/config",
	"network/interface/lan/config",
	"network/interface/wan1/config",
	"network/interface/wan1/resume",
	"network/interface/wan1/suspend",
	"reboot/",
}

var exactHighRisk = map[string]struct{}{
	"dhcpd/config/set":    {},
	"wireless/band/set":   {},
	"wireless/bss/clear":  {},
	"wireless/bss/set":    {},
	"wireless/client/set": {},
	"wireless/mac/add":    {},
	"wireless/mac/del":    {},
	"wireless/mac/policy": {},
}

func Assess(method string, hasParams bool) Assessment {
	trimmed := strings.TrimSpace(method)
	if trimmed == "" || trimmed != method || trimmed != strings.ToLower(trimmed) || !validMethodName(trimmed) {
		return Assessment{Kind: Blocked, Reason: "method names must use lowercase ASCII letters, numbers, slash, underscore, or hyphen"}
	}
	method = trimmed
	if _, dual := dualMethods[method]; !dual || !hasParams {
		if _, ok := exactReads[method]; ok {
			return Assessment{Kind: Read, Reason: "known read-only UI method"}
		}
	}
	if reason, ok := blockedMethods[method]; ok {
		return Assessment{Kind: Blocked, Reason: reason}
	}
	for prefix, reason := range blockedPrefixes {
		if method == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(method, prefix) {
			return Assessment{Kind: Blocked, Reason: reason}
		}
	}
	for _, prefix := range highRiskPrefixes {
		if strings.HasPrefix(method, prefix) {
			return Assessment{Kind: HighRisk, Reason: "may interrupt access, replace configuration, credentials, or firmware"}
		}
	}
	if _, ok := exactHighRisk[method]; ok {
		return Assessment{Kind: HighRisk, Reason: "may disconnect clients or remove wireless configuration"}
	}
	if _, ok := dualMethods[method]; ok && hasParams {
		return Assessment{Kind: Write, Reason: "this method changes state when params are present"}
	}
	if _, ok := exactWrites[method]; ok {
		return Assessment{Kind: Write, Reason: "known state-changing UI method"}
	}
	return Assessment{Kind: Unknown, Reason: "method has not been classified for this release"}
}

// RequiresParams reports whether a classified exact state-changing method has
// no meaningful parameterless form in the observed UI protocol.
func RequiresParams(method string) bool {
	_, ok := exactWrites[method]
	return ok
}

func validMethodName(method string) bool {
	if strings.HasPrefix(method, "/") || strings.HasSuffix(method, "/") || strings.Contains(method, "//") {
		return false
	}
	for _, char := range method {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '/' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
