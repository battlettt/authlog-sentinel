package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const samplePath = "examples/sample-auth.log"

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut strings.Builder
	p := &Parser{Now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), Loc: time.UTC}
	code := run(args, strings.NewReader(stdin), &out, &errOut, p)
	return code, out.String(), errOut.String()
}

func TestRunSampleText(t *testing.T) {
	code, out, errOut := runCLI(t, "", samplePath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"FLAGGED IPs (3)", "203.0.113.77", "198.51.100.23", "2001:db8:dead:beef::7", "malformed (skipped)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Slow brute force is not flagged at the default 60m window...
	flaggedSection := out[:strings.Index(out, "Below threshold")]
	if strings.Contains(flaggedSection, "198.51.100.200") {
		t.Error("slow brute force should be below threshold at 60m")
	}
}

func TestRunSampleJSONWiderWindow(t *testing.T) {
	code, out, errOut := runCLI(t, "", "--format", "json", "--window", "2h", samplePath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	flagged := map[string]jsonIP{}
	for _, ip := range rep.IPs {
		if ip.Flagged {
			flagged[ip.IP] = ip
		}
	}
	// ...but is caught with a 2h window.
	if _, ok := flagged["198.51.100.200"]; !ok || rep.FlaggedCount != 4 {
		t.Errorf("expected slow brute force flagged at 2h; flagged=%v", flagged)
	}
	stuff := flagged["203.0.113.77"]
	if stuff.Failures != 12 || stuff.DistinctUsers != 12 || stuff.Score != 48 || stuff.Rank != 1 {
		t.Errorf("credential stuffing entry = %+v", stuff)
	}
	if rep.Malformed == 0 || rep.Ignored == 0 {
		t.Errorf("sample should exercise skipped lines: %+v", rep)
	}
}

func TestRunStdinBlocklist(t *testing.T) {
	stdin := strings.Repeat("Oct 28 03:00:00 h sshd[1]: Failed password for root from 198.51.100.9 port 1 ssh2\n", 10) +
		"Oct 28 03:00:00 h sshd[1]: Failed password for alice from 192.0.2.1 port 1 ssh2\n"
	code, out, errOut := runCLI(t, stdin, "--blocklist", "-")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "\n198.51.100.9\n") || strings.Contains(out, "192.0.2.1") {
		t.Errorf("blocklist output wrong:\n%s", out)
	}
}

func TestRunMultipleInputs(t *testing.T) {
	stdin := strings.Repeat("Oct 28 05:31:00 h sshd[1]: Failed password for root from 198.51.100.200 port 1 ssh2\n", 2)
	code, out, _ := runCLI(t, stdin, "--format", "json", samplePath, "-")
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) != 2 || rep.Inputs[1] != "(stdin)" {
		t.Errorf("inputs = %v", rep.Inputs)
	}
}

func TestRunUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"--window", "0s", samplePath},
		{"--window", "banana", samplePath},
		{"--threshold", "0", samplePath},
		{"--min-users", "0", samplePath},
		{"--format", "xml", samplePath},
		{"--blocklist", "--format", "json", samplePath},
		{"-", "-"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, "", args...); code != 2 {
			t.Errorf("args %v: exit %d, want 2", args, code)
		}
	}
	if code, _, errOut := runCLI(t, "", "does-not-exist.log"); code != 1 || errOut == "" {
		t.Errorf("missing file: exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := runCLI(t, "", "-h"); code != 0 {
		t.Errorf("-h: exit %d", code)
	}
}
