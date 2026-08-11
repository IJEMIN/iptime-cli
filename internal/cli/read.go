package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/IJEMIN/iptime-cli/internal/client"
	"github.com/IJEMIN/iptime-cli/internal/redact"
	"github.com/IJEMIN/iptime-cli/internal/safety"
)

type methodCall struct {
	Method string
	Params any
}

func statusMethods() []methodCall {
	return []methodCall{
		{Method: "product/info"},
		{Method: "system/name"},
		{Method: "network/interface/lan/info"},
		{Method: "network/interface/wan1/info"},
		{Method: "network/dns/info"},
	}
}

func dhcpMethods() []methodCall {
	return []methodCall{
		{Method: "dhcpd/config/get", Params: "lan"},
		{Method: "dhcpd/status", Params: "lan"},
		{Method: "dhcpd/lease/show", Params: "lan"},
	}
}

func wifiMethods() []methodCall {
	return []methodCall{
		{Method: "wireless/info"},
		{Method: "wireless/band/show"},
		{Method: "wireless/bss/show"},
	}
}

func portForwardMethods() []methodCall {
	return []methodCall{
		{Method: "portforward/config"},
		{Method: "portforward/get", Params: "user"},
	}
}

func (a *App) runReadGroup(command string, calls []methodCall) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		items := make([]map[string]any, 0, len(calls))
		partial := false
		successes := 0
		var firstRPCError error
		for _, call := range calls {
			value, err := router.RPC(ctx, call.Method, call.Params)
			if err != nil {
				var rpcErr *client.RPCError
				if errors.As(err, &rpcErr) && rpcErr.Code != -31998 {
					partial = true
					if firstRPCError == nil {
						firstRPCError = fmt.Errorf("%s: %w", call.Method, err)
					}
					items = append(items, map[string]any{
						"method": call.Method,
						"error":  map[string]any{"kind": "router_rpc", "code": rpcErr.Code},
					})
					continue
				}
				return nil, fmt.Errorf("%s: %w", call.Method, err)
			}
			items = append(items, map[string]any{"method": call.Method, "result": value})
			successes++
		}
		if successes == 0 && firstRPCError != nil {
			return nil, firstRPCError
		}
		return map[string]any{"items": items, "partial": partial}, nil
	})
	if err != nil {
		return err
	}
	return a.writeSuccess(command, result)
}

func (a *App) runCall(args []string) error {
	flags := flag.NewFlagSet("call", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	paramsJSON := flags.String("params", "", "JSON params (must not contain secrets)")
	paramsStdin := flags.Bool("params-stdin", false, "read JSON params from one stdin line")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printCommandUsage("call")
			return nil
		}
		return usageError(err.Error())
	}
	if flags.NArg() != 1 {
		return usageError("usage: iptime call [--params JSON] <method>")
	}
	method := flags.Arg(0)
	preAssessment := safety.Assess(method, *paramsJSON != "" || *paramsStdin)
	if preAssessment.Kind == safety.Blocked {
		return &cliError{Kind: "safety", Message: fmt.Sprintf("method %q is %s, not a classified read; use apply for writes", method, preAssessment.Kind)}
	}
	params, hasParams, fromStdin, err := a.parseParams(*paramsJSON, *paramsStdin)
	if err != nil {
		return err
	}
	if !fromStdin && redact.ContainsSecrets(params) {
		return usageError("secret-like params must use --params-stdin, not --params")
	}
	assessment := safety.Assess(method, hasParams)
	if assessment.Kind != safety.Read {
		return &cliError{Kind: "safety", Message: fmt.Sprintf("method %q is %s, not a classified read; use apply for writes", method, assessment.Kind)}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := a.withAuth(ctx, func(router *client.Client) (any, error) {
		return router.RPC(ctx, method, params)
	})
	if err != nil {
		return err
	}
	return a.writeSuccess("call", map[string]any{"method": method, "result": result})
}

func (a *App) parseParams(raw string, fromStdin bool) (any, bool, bool, error) {
	if raw != "" && fromStdin {
		return nil, false, false, usageError("use only one of --params and --params-stdin")
	}
	if fromStdin {
		line, err := a.readLine()
		if err != nil {
			return nil, false, false, fmt.Errorf("read params from stdin: %w", err)
		}
		raw = line
	}
	value, hasValue, err := parseJSONParam(raw)
	if hasValue && value == nil {
		return nil, false, fromStdin, usageError("JSON null is not a supported params value; omit params instead")
	}
	return value, hasValue, fromStdin, err
}

func parseJSONParam(raw string) (any, bool, error) {
	if raw == "" {
		return nil, false, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false, usageError("invalid --params JSON: " + err.Error())
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false, usageError("--params must contain exactly one JSON value")
	}
	return value, true, nil
}
