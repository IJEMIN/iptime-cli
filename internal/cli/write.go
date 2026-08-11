package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IJEMIN/iptime-cli/internal/client"
	"github.com/IJEMIN/iptime-cli/internal/safety"
)

const minBackupBytes = 256

func (a *App) runApply(args []string) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	paramsJSON := flags.String("params", "", "deprecated for writes; use --params-stdin")
	paramsStdin := flags.Bool("params-stdin", false, "read JSON params from one stdin line")
	yes := flags.Bool("yes", false, "execute instead of printing a dry run")
	forceHighRisk := flags.Bool("force-high-risk", false, "acknowledge a high-risk method")
	forceUnknown := flags.Bool("force-unknown", false, "acknowledge an unclassified method")
	noBackup := flags.Bool("no-backup", false, "skip the automatic local pre-change backup")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("apply")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 1 {
		return usageError("usage: iptime apply [options] <method>")
	}
	if *paramsJSON != "" {
		return usageError("raw write params must use --params-stdin so values never appear in process arguments")
	}
	method := flags.Arg(0)
	preAssessment := safety.Assess(method, *paramsStdin)
	if preAssessment.Kind == safety.Blocked {
		return &cliError{Kind: "safety", Message: fmt.Sprintf("method %q is blocked: %s", method, preAssessment.Reason)}
	}
	params, hasParams, _, err := a.parseParams("", *paramsStdin)
	if err != nil {
		return err
	}
	assessment := safety.Assess(method, hasParams)
	if assessment.Kind == safety.Blocked {
		return &cliError{Kind: "safety", Message: fmt.Sprintf("method %q is blocked: %s", method, assessment.Reason)}
	}
	if assessment.Kind == safety.Read {
		return &cliError{Kind: "safety", Message: fmt.Sprintf("method %q is read-only; use call", method)}
	}
	if safety.RequiresParams(method) && !hasParams {
		return usageError("known write methods require an explicit non-null params value")
	}
	if assessment.Kind == safety.HighRisk && !*forceHighRisk && *yes {
		return &cliError{Kind: "safety", Message: "execution requires --force-high-risk as a second acknowledgement"}
	}
	if assessment.Kind == safety.Unknown && !*forceUnknown && *yes {
		return &cliError{Kind: "safety", Message: "execution requires --force-unknown as a second acknowledgement"}
	}
	plan := map[string]any{"dry_run": !*yes, "method": method, "params": params, "assessment": assessment, "pre_change_backup": !*noBackup}
	if !*yes {
		return a.writeSuccess("apply", plan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		backupPath := ""
		if !*noBackup {
			path, backupErr := a.automaticBackup(ctx, router)
			if backupErr != nil {
				return nil, fmt.Errorf("create pre-change backup: %w; retry with --no-backup only if intentional", backupErr)
			}
			backupPath = path
			plan["backup_file"] = backupPath
		}
		value, err := router.RPC(ctx, method, params)
		if err != nil && backupPath != "" {
			return nil, afterBackupError(backupPath, "write failed", err)
		}
		return value, err
	})
	if err != nil {
		return err
	}
	plan["result"] = result
	return a.writeSuccess("apply", plan)
}

func (a *App) runBackup(args []string) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "destination .config file (required)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("backup")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 0 || *output == "" {
		return usageError("usage: iptime backup --output <path.config>")
	}
	if filepath.Ext(*output) != ".config" {
		return usageError("backup output must use the .config extension so repository ignore rules can protect it")
	}
	if _, err := os.Lstat(*output); err == nil {
		return fmt.Errorf("backup destination already exists: %s", safeBase(*output))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		return fetchBackup(ctx, router)
	})
	if err != nil {
		return err
	}
	raw := result.([]byte)
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	name := file.Name()
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write backup: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return fmt.Errorf("sync backup: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close backup: %w", err)
	}
	return a.writeSuccess("backup", map[string]any{
		"saved":   true,
		"file":    safeBase(name),
		"bytes":   len(raw),
		"warning": "This file may contain credentials and must never be committed or shared.",
	})
}

func (a *App) runWiFi(args []string) error {
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		a.printCommandUsage("wifi")
		return nil
	}
	if len(args) == 0 || args[0] == "show" {
		if len(args) > 1 {
			return usageError("wifi show takes no arguments")
		}
		return a.runReadGroup("wifi show", wifiMethods())
	}
	if args[0] != "set" {
		return usageError("wifi requires show or set")
	}
	flags := flag.NewFlagSet("wifi set", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bss := flags.String("bss", "", "BSS identifier from wifi show (required)")
	ssid := &optionalString{}
	authenc := &optionalString{}
	enable := &optionalBool{}
	hide := &optionalBool{}
	flags.Var(ssid, "ssid", "new SSID")
	flags.Var(authenc, "authenc", "new auth/encryption mode")
	flags.Var(enable, "enable", "true or false")
	flags.Var(hide, "hide", "true or false")
	setPassword := flags.Bool("set-password", false, "prompt for a new Wi-Fi password")
	wifiPasswordStdin := flags.Bool("wifi-password-stdin", false, "read a new Wi-Fi password from the next stdin line")
	yes := flags.Bool("yes", false, "apply the change")
	noBackup := flags.Bool("no-backup", false, "skip the automatic local pre-change backup")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("wifi")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 0 || *bss == "" {
		return usageError("usage: iptime wifi set --bss <id> [changes] [--yes]")
	}
	if *setPassword && *wifiPasswordStdin {
		return usageError("use only one of --set-password and --wifi-password-stdin")
	}
	if !ssid.set && !authenc.set && !enable.set && !hide.set && !*setPassword && !*wifiPasswordStdin {
		return usageError("wifi set requires at least one change")
	}
	if authenc.set && !knownAuthenc(authenc.value) {
		return usageError("--authenc is not one of the modes supported by this release")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		current, err := router.RPC(ctx, "wireless/bss/show", nil)
		if err != nil {
			return nil, err
		}
		list, ok := current.([]any)
		if !ok {
			return nil, errors.New("wireless/bss/show returned an unexpected result")
		}
		pureDisable := enable.set && !enable.value && !ssid.set && !authenc.set && !hide.set && !*setPassword && !*wifiPasswordStdin
		var selected map[string]any
		for _, item := range list {
			candidate, ok := item.(map[string]any)
			candidateBSS, validBSS := candidate["bss"].(string)
			if ok && validBSS && candidateBSS == *bss {
				if pureDisable {
					selected = map[string]any{"bss": *bss, "enable": false}
				} else {
					selected, err = bssSetParams(candidate, *setPassword || *wifiPasswordStdin)
				}
				if err != nil {
					return nil, err
				}
				break
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("BSS %q was not found", *bss)
		}
		if ssid.set {
			selected["ssid"] = ssid.value
		}
		if authenc.set {
			selected["authenc"] = authenc.value
		}
		if enable.set {
			selected["enable"] = enable.value
		}
		if hide.set {
			selected["hide"] = hide.value
		}
		if *setPassword || *wifiPasswordStdin {
			var password string
			if *wifiPasswordStdin {
				password, err = a.readLine()
			} else {
				password, err = a.readSecret("New Wi-Fi password: ")
			}
			if err != nil {
				return nil, err
			}
			selected["password"] = password
			password = ""
		}
		if !pureDisable {
			if err := validateBSSSetParams(selected, false); err != nil {
				return nil, err
			}
		}
		expectedState := make(map[string]any, len(selected))
		for key, value := range selected {
			expectedState[key] = value
		}
		selected["commit"] = true
		plan := map[string]any{"dry_run": !*yes, "method": "wireless/bss/set", "params": selected, "pre_change_backup": !*noBackup}
		if !*yes {
			return plan, nil
		}
		backupPath := ""
		if !*noBackup {
			path, backupErr := a.automaticBackup(ctx, router)
			if backupErr != nil {
				return nil, fmt.Errorf("create pre-change backup: %w; retry with --no-backup only if intentional", backupErr)
			}
			backupPath = path
			plan["backup_file"] = backupPath
		}
		writeResult, err := router.RPC(ctx, "wireless/bss/set", selected)
		if err != nil {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, "Wi-Fi write failed", err)
			}
			return nil, err
		}
		verified, err := router.RPC(ctx, "wireless/bss/show", nil)
		if err != nil {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, "Wi-Fi verification failed", err)
			}
			return nil, fmt.Errorf("change applied but verification failed: %w", err)
		}
		verifiedBSS := findBSS(verified, *bss)
		if verifiedBSS == nil {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, "Wi-Fi verification could not find the BSS", nil)
			}
			return nil, errors.New("change applied but verification could not find the BSS")
		}
		if field, ok := subsetMatches(expectedState, verifiedBSS); !ok {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, fmt.Sprintf("Wi-Fi verification did not match field %q", field), nil)
			}
			return nil, fmt.Errorf("change applied but verification did not match field %q", field)
		}
		plan["result"] = writeResult
		plan["verified"] = map[string]any{"matched": true, "bss": verifiedBSS}
		return plan, nil
	})
	if err != nil {
		return err
	}
	return a.writeSuccess("wifi set", result)
}

func findBSS(value any, bss string) map[string]any {
	list, _ := value.([]any)
	for _, item := range list {
		candidate, ok := item.(map[string]any)
		candidateBSS, validBSS := candidate["bss"].(string)
		if ok && validBSS && candidateBSS == bss {
			return candidate
		}
	}
	return nil
}

func bssSetParams(current map[string]any, replacingPassword bool) (map[string]any, error) {
	allowed := []string{
		"bss", "enable", "ssid", "hide", "authenc", "password", "channel",
		"radius", "access", "maxsta", "band",
	}
	result := make(map[string]any, len(allowed)+1)
	for _, key := range allowed {
		if key == "password" && replacingPassword {
			result[key] = nil
			continue
		}
		value, ok := current[key]
		if !ok {
			return nil, fmt.Errorf("wireless/bss/show omitted required field %q", key)
		}
		result[key] = value
	}
	radius, err := normalizedRadius(result["radius"])
	if err != nil {
		return nil, err
	}
	result["radius"] = radius
	if err := validateBSSSetParams(result, replacingPassword); err != nil {
		return nil, err
	}
	return result, nil
}

func validateBSSSetParams(params map[string]any, allowMissingPersonalPassword bool) error {
	bss, ok := params["bss"].(string)
	if !ok || bss == "" {
		return errors.New("wireless/bss/show returned an invalid bss field")
	}
	enabled, ok := params["enable"].(bool)
	if !ok {
		return errors.New("wireless/bss/show returned an invalid enable field")
	}
	ssid, ok := params["ssid"].(string)
	if !ok {
		return errors.New("wireless/bss/show returned an invalid ssid field")
	}
	if enabled && ssid == "" {
		return errors.New("an enabled BSS must have a non-empty SSID")
	}
	if _, ok := params["hide"].(bool); !ok {
		return errors.New("wireless/bss/show returned an invalid hide field")
	}
	authenc, ok := params["authenc"].(string)
	if !ok || authenc == "" {
		return errors.New("wireless/bss/show returned an invalid authenc field")
	}
	password, passwordIsString := params["password"].(string)
	if params["password"] != nil && !passwordIsString {
		return errors.New("wireless/bss/show returned an invalid password field")
	}
	lowerAuth := strings.ToLower(authenc)
	if requiresPersonalPassword(lowerAuth) && !allowMissingPersonalPassword {
		if !passwordIsString || password == "" {
			return errors.New("wireless/bss/show did not provide the existing personal Wi-Fi password; refusing read-modify-write")
		}
	}
	if channel, ok := params["channel"].(string); !ok || channel == "" {
		return errors.New("wireless/bss/show returned an invalid channel field")
	}
	if access, ok := params["access"].(string); !ok || access == "" {
		return errors.New("wireless/bss/show returned an invalid access field")
	}
	maxsta, ok := integerValue(params["maxsta"])
	if !ok || maxsta < 0 || maxsta > 65535 {
		return errors.New("wireless/bss/show returned an invalid maxsta field")
	}
	bands, ok := params["band"].([]any)
	if !ok || len(bands) == 0 {
		return errors.New("wireless/bss/show returned an invalid band field")
	}
	for _, band := range bands {
		if value, ok := band.(string); !ok || value == "" {
			return errors.New("wireless/bss/show returned an invalid band field")
		}
	}
	if requiresRadius(lowerAuth) {
		radius, ok := params["radius"].(map[string]any)
		if !ok || radius["server"] == "" || radius["secret"] == "" {
			return errors.New("wireless/bss/show did not provide a complete RADIUS configuration; refusing read-modify-write")
		}
	}
	return nil
}

func requiresPersonalPassword(authenc string) bool {
	return strings.Contains(authenc, "psk") || strings.Contains(authenc, "sae") || strings.Contains(authenc, "wep")
}

func normalizedRadius(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	radius, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("wireless/bss/show returned an invalid radius field")
	}
	result := make(map[string]any, 4)
	for _, key := range []string{"server", "port", "enable_port", "secret"} {
		item, exists := radius[key]
		if !exists {
			return nil, fmt.Errorf("wireless/bss/show omitted required radius field %q", key)
		}
		result[key] = item
	}
	if _, ok := result["server"].(string); !ok {
		return nil, errors.New("wireless/bss/show returned an invalid radius server")
	}
	port, ok := integerValue(result["port"])
	if !ok || port < 1 || port > 65535 {
		return nil, errors.New("wireless/bss/show returned an invalid radius port")
	}
	if _, ok := result["enable_port"].(bool); !ok {
		return nil, errors.New("wireless/bss/show returned an invalid radius enable_port")
	}
	if _, ok := result["secret"].(string); !ok {
		return nil, errors.New("wireless/bss/show returned an invalid radius secret")
	}
	return result, nil
}

func requiresRadius(authenc string) bool {
	switch authenc {
	case "wpa2_aes", "wpawpa2_aestkip", "wpa_aes", "shared_aes", "wpa3_aes":
		return true
	default:
		return false
	}
}

func knownAuthenc(value string) bool {
	_, ok := map[string]struct{}{
		"wpa2psk_aes": {}, "wpa3saewpa2psk_aes": {}, "wpa3sae_aes": {},
		"wpapskwpa2psk_aes": {}, "wpapsk_aes": {}, "wpa2psk_aestkip": {},
		"wpapskwpa2psk_aestkip": {}, "wpapsk_aestkip": {}, "wpapsk_tkip": {},
		"auto_wep": {}, "open_wep": {}, "shared_wep": {}, "open_none": {},
		"wpa2_aes": {}, "wpawpa2_aestkip": {}, "wpa_aes": {}, "owe_aes": {},
		"shared_aes": {}, "wpa3_aes": {},
	}[value]
	return ok
}

func (a *App) runPortForward(args []string) error {
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		a.printCommandUsage("port-forward")
		return nil
	}
	if len(args) == 0 || args[0] == "list" {
		if len(args) > 1 {
			return usageError("port-forward list takes no arguments")
		}
		return a.runReadGroup("port-forward list", portForwardMethods())
	}
	switch args[0] {
	case "add":
		return a.runPortForwardAdd(args[1:])
	case "delete":
		return a.runPortForwardDelete(args[1:])
	default:
		return usageError("port-forward requires list, add, or delete")
	}
}

func (a *App) runPortForwardAdd(args []string) error {
	flags := flag.NewFlagSet("port-forward add", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "unique rule name")
	target := flags.String("target", "", "private target IPv4 address")
	protocol := flags.String("protocol", "tcp", "tcp, udp, or tcpudp")
	externalPort := flags.Int("external-port", 0, "WAN-side port")
	externalEnd := flags.Int("external-end", 0, "optional WAN-side range end")
	internalPort := flags.Int("internal-port", 0, "target port")
	internalEnd := flags.Int("internal-end", 0, "optional target range end")
	priority := flags.Int("priority", 0, "optional rule priority")
	yes := flags.Bool("yes", false, "apply the change")
	noBackup := flags.Bool("no-backup", false, "skip the automatic local pre-change backup")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("port-forward")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 0 || *name == "" || *target == "" || *externalPort == 0 || *internalPort == 0 {
		return usageError("port-forward add requires --name, --target, --external-port, and --internal-port")
	}
	parsedTarget := net.ParseIP(*target)
	if parsedTarget == nil || parsedTarget.To4() == nil || strings.Contains(*target, ":") || !parsedTarget.IsPrivate() {
		return usageError("--target must be a private IPv4 address")
	}
	canonicalTarget := parsedTarget.To4().String()
	if !oneOf(*protocol, "tcp", "udp", "tcpudp") {
		return usageError("--protocol must be tcp, udp, or tcpudp")
	}
	if err := validatePortRange(*externalPort, *externalEnd); err != nil {
		return usageError("external ports: " + err.Error())
	}
	if err := validatePortRange(*internalPort, *internalEnd); err != nil {
		return usageError("internal ports: " + err.Error())
	}
	if *priority < 0 {
		return usageError("--priority must be zero or greater")
	}
	params := map[string]any{
		"name":     *name,
		"active":   true,
		"protocol": *protocol,
		"target":   canonicalTarget,
		"src":      portRange(*externalPort, *externalEnd),
		"dst":      portRange(*internalPort, *internalEnd),
	}
	if *priority > 0 {
		params["priority"] = *priority
	}
	return a.executeKnownWrite("port-forward add", "portforward/add", params, *yes, *noBackup, func(ctx context.Context, router *client.Client) (any, error) {
		value, err := router.RPC(ctx, "portforward/get", "user")
		if err != nil {
			return nil, err
		}
		rule := findRule(value, *name)
		if rule == nil {
			return nil, fmt.Errorf("rule %q was not found after apply", *name)
		}
		if field, ok := subsetMatches(params, rule); !ok {
			return nil, fmt.Errorf("rule was created but verification did not match field %q", field)
		}
		return map[string]any{"matched": true, "rule": rule}, nil
	})
}

func (a *App) runPortForwardDelete(args []string) error {
	flags := flag.NewFlagSet("port-forward delete", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	names := &stringList{}
	flags.Var(names, "name", "rule name; repeat for multiple rules")
	ruleType := flags.String("type", "user", "user or upnp")
	yes := flags.Bool("yes", false, "apply the change")
	noBackup := flags.Bool("no-backup", false, "skip the automatic local pre-change backup")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("port-forward")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 0 || len(*names) == 0 {
		return usageError("port-forward delete requires at least one --name")
	}
	if !oneOf(*ruleType, "user", "upnp") {
		return usageError("--type must be user or upnp")
	}
	params := map[string]any{"type": *ruleType, "list": []string(*names)}
	return a.executeKnownWrite("port-forward delete", "portforward/del", params, *yes, *noBackup, func(ctx context.Context, router *client.Client) (any, error) {
		value, err := router.RPC(ctx, "portforward/get", *ruleType)
		if err != nil {
			return nil, err
		}
		for _, name := range *names {
			if findRule(value, name) != nil {
				return nil, fmt.Errorf("rule %q still exists after delete", name)
			}
		}
		return map[string]any{"matched": true, "absent": []string(*names)}, nil
	})
}

func (a *App) executeKnownWrite(command, method string, params any, yes, noBackup bool, verify func(context.Context, *client.Client) (any, error)) error {
	plan := map[string]any{"dry_run": !yes, "method": method, "params": params, "assessment": safety.Assess(method, true), "pre_change_backup": !noBackup}
	if !yes {
		return a.writeSuccess(command, plan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		backupPath := ""
		if !noBackup {
			path, backupErr := a.automaticBackup(ctx, router)
			if backupErr != nil {
				return nil, fmt.Errorf("create pre-change backup: %w; retry with --no-backup only if intentional", backupErr)
			}
			backupPath = path
			plan["backup_file"] = backupPath
		}
		writeResult, err := router.RPC(ctx, method, params)
		if err != nil {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, "write failed", err)
			}
			return nil, err
		}
		verified, err := verify(ctx, router)
		if err != nil {
			if backupPath != "" {
				return nil, afterBackupError(backupPath, "verification failed", err)
			}
			return nil, fmt.Errorf("change applied but verification failed: %w", err)
		}
		return map[string]any{"result": writeResult, "verified": verified}, nil
	})
	if err != nil {
		return err
	}
	plan["result"] = result
	return a.writeSuccess(command, plan)
}

func afterBackupError(backupPath, message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%s after local backup was saved at %s", message, backupPath)
	}
	return fmt.Errorf("%s after local backup was saved at %s: %w", message, backupPath, cause)
}

func fetchBackup(ctx context.Context, router *client.Client) ([]byte, error) {
	result, err := router.RPC(ctx, "config/backup", nil)
	if err != nil {
		return nil, err
	}
	encoded, ok := result.(string)
	if !ok {
		return nil, errors.New("router returned a non-string config backup")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode router config backup: %w", err)
	}
	if len(raw) < minBackupBytes {
		return nil, fmt.Errorf("router returned an implausibly small config backup (%d bytes)", len(raw))
	}
	return raw, nil
}

func (a *App) automaticBackup(ctx context.Context, router *client.Client) (string, error) {
	raw, err := fetchBackup(ctx, router)
	if err != nil {
		return "", err
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate macOS application support: %w", err)
	}
	digest := sha256.Sum256([]byte(router.RouterOrigin()))
	routerID := hex.EncodeToString(digest[:6])
	dir := filepath.Join(configDir, "iptime-cli", "backups", routerID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure backup directory: %w", err)
	}
	prefix := "pre-change-" + time.Now().Format("20060102-150405") + "-"
	file, err := os.CreateTemp(dir, prefix+"*.config")
	if err != nil {
		return "", fmt.Errorf("create backup file: %w", err)
	}
	name := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("write backup file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("sync backup file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("close backup file: %w", err)
	}
	return displayLocalPath(name), nil
}

func displayLocalPath(path string) string {
	home, err := os.UserHomeDir()
	if err == nil {
		if relative, err := filepath.Rel(home, path); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.Join("~", relative)
		}
	}
	return safeBase(path)
}

func validatePortRange(start, end int) error {
	if start < 1 || start > 65535 {
		return errors.New("start must be between 1 and 65535")
	}
	if end != 0 && (end < start || end > 65535) {
		return errors.New("end must be zero or between start and 65535")
	}
	return nil
}

func portRange(start, end int) map[string]any {
	result := map[string]any{"start": start}
	if end != 0 && end != start {
		result["end"] = end
	}
	return result
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func findRule(value any, name string) map[string]any {
	list, _ := value.([]any)
	for _, item := range list {
		candidate, ok := item.(map[string]any)
		if ok && fmt.Sprint(candidate["name"]) == name {
			return candidate
		}
	}
	return nil
}

// subsetMatches compares only fields the CLI intentionally changed. JSON
// numbers and Go integer values compare by their lossless string form.
func subsetMatches(expected, actual map[string]any) (string, bool) {
	for key, expectedValue := range expected {
		actualValue, exists := actual[key]
		if !exists || !valueMatches(expectedValue, actualValue) {
			return key, false
		}
	}
	return "", true
}

func valueMatches(expected, actual any) bool {
	switch expectedValue := expected.(type) {
	case map[string]any:
		actualValue, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		_, ok = subsetMatches(expectedValue, actualValue)
		return ok
	case []string:
		actualList, ok := actual.([]any)
		if !ok || len(expectedValue) != len(actualList) {
			return false
		}
		for i := range expectedValue {
			actualValue, ok := actualList[i].(string)
			if !ok || expectedValue[i] != actualValue {
				return false
			}
		}
		return true
	case []any:
		actualList, ok := actual.([]any)
		if !ok || len(expectedValue) != len(actualList) {
			return false
		}
		for i := range expectedValue {
			if !valueMatches(expectedValue[i], actualList[i]) {
				return false
			}
		}
		return true
	default:
		if expectedNumber, ok := numericText(expected); ok {
			actualNumber, ok := numericText(actual)
			if !ok {
				return false
			}
			expectedRat, expectedOK := new(big.Rat).SetString(expectedNumber)
			actualRat, actualOK := new(big.Rat).SetString(actualNumber)
			return expectedOK && actualOK && expectedRat.Cmp(actualRat) == 0
		}
		switch expectedValue := expected.(type) {
		case string:
			actualValue, ok := actual.(string)
			return ok && expectedValue == actualValue
		case bool:
			actualValue, ok := actual.(bool)
			return ok && expectedValue == actualValue
		case nil:
			return actual == nil
		default:
			return false
		}
	}
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		result, err := strconv.ParseInt(typed.String(), 10, 64)
		return result, err == nil
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case float32:
		value := float64(typed)
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < math.MinInt64 || value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < math.MinInt64 || typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func numericText(value any) (string, bool) {
	switch typed := value.(type) {
	case json.Number:
		return typed.String(), true
	case int:
		return strconv.FormatInt(int64(typed), 10), true
	case int8:
		return strconv.FormatInt(int64(typed), 10), true
	case int16:
		return strconv.FormatInt(int64(typed), 10), true
	case int32:
		return strconv.FormatInt(int64(typed), 10), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	case float32:
		value := float64(typed)
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return "", false
		}
		return strconv.FormatFloat(value, 'g', -1, 32), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return "", false
		}
		return strconv.FormatFloat(typed, 'g', -1, 64), true
	default:
		return "", false
	}
}

type optionalString struct {
	value string
	set   bool
}

func (v *optionalString) String() string { return v.value }
func (v *optionalString) Set(value string) error {
	v.value = value
	v.set = true
	return nil
}

type optionalBool struct {
	value bool
	set   bool
}

func (v *optionalBool) String() string { return strconv.FormatBool(v.value) }
func (v *optionalBool) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	v.value = parsed
	v.set = true
	return nil
}

type stringList []string

func (v *stringList) String() string { return strings.Join(*v, ",") }
func (v *stringList) Set(value string) error {
	if value == "" {
		return errors.New("name cannot be empty")
	}
	*v = append(*v, value)
	return nil
}
