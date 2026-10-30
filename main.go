// Command authlog-sentinel reads Linux SSH auth logs and reports source IPs
// that look like brute-force or credential-stuffing attackers.
//
// It only reads logs and prints reports. It never blocks anything, never
// touches the firewall, and never modifies the system.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usageText = `Usage: authlog-sentinel [flags] FILE [FILE...]
       authlog-sentinel [flags] -          (read from stdin)

Detects SSH brute-force and credential-stuffing source IPs in syslog-format
auth logs. Read-only: it never blocks IPs or modifies the system.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, NewParser()))
}

// run is the testable entry point. Exit codes: 0 ok, 1 runtime error, 2 usage error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, parser *Parser) int {
	fs := flag.NewFlagSet("authlog-sentinel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := DefaultConfig()
	fs.DurationVar(&cfg.Window, "window", cfg.Window, "sliding time window, e.g. 30m, 2h")
	fs.IntVar(&cfg.Threshold, "threshold", cfg.Threshold, "flag an IP with at least this many failures in a window")
	fs.IntVar(&cfg.MinUsers, "min-users", cfg.MinUsers, "flag an IP trying at least this many distinct usernames in a window")
	format := fs.String("format", "text", "report format: text or json")
	blocklist := fs.Bool("blocklist", false, "print flagged IPs plus commented iptables/nftables suggestions instead of the report")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "authlog-sentinel: "+format+"\n", a...)
		return 2
	}
	switch {
	case fs.NArg() == 0:
		return usageErr("no input given; pass one or more log files, or - for stdin")
	case cfg.Window <= 0:
		return usageErr("--window must be positive, got %s", cfg.Window)
	case cfg.Threshold < 1:
		return usageErr("--threshold must be at least 1, got %d", cfg.Threshold)
	case cfg.MinUsers < 1:
		return usageErr("--min-users must be at least 1, got %d", cfg.MinUsers)
	case *format != "text" && *format != "json":
		return usageErr("--format must be text or json, got %q", *format)
	case *blocklist && *format == "json":
		return usageErr("--blocklist and --format json cannot be combined")
	}

	var events []Event
	var stats ParseStats
	stdinUsed := false
	for _, name := range fs.Args() {
		var evs []Event
		var st ParseStats
		var err error
		if name == "-" {
			if stdinUsed {
				return usageErr("stdin (-) given more than once")
			}
			stdinUsed = true
			evs, st, err = parser.Parse(stdin)
		} else {
			var f *os.File
			if f, err = os.Open(name); err != nil {
				fmt.Fprintf(stderr, "authlog-sentinel: %v\n", err)
				return 1
			}
			evs, st, err = parser.Parse(f)
			f.Close()
		}
		if err != nil {
			fmt.Fprintf(stderr, "authlog-sentinel: reading %s: %v\n", name, err)
			return 1
		}
		events = append(events, evs...)
		stats.Add(st)
	}

	inputs := make([]string, len(fs.Args()))
	for i, a := range fs.Args() {
		inputs[i] = a
		if a == "-" {
			inputs[i] = "(stdin)"
		}
	}
	s := Summary{Inputs: inputs, Stats: stats, Config: cfg, Reports: Analyze(events, cfg)}

	var err error
	switch {
	case *blocklist:
		err = WriteBlocklist(stdout, s)
	case *format == "json":
		err = WriteJSON(stdout, s)
	default:
		err = WriteText(stdout, s)
	}
	if err != nil {
		fmt.Fprintf(stderr, "authlog-sentinel: writing output: %v\n", err)
		return 1
	}
	return 0
}
