package main

import (
	"os"

	"github.com/IJEMIN/iptime-cli/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	code := cli.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	os.Exit(code)
}
