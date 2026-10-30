package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestWriteTextRankedReport(t *testing.T) {
	s := blocklistFixture()
	s.Inputs = []string{"auth.log"}
	var b strings.Builder
	if err := WriteText(&b, s); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"FLAGGED IPs (3)", "Below threshold (2)", "auth.log", "failures + 3 x distinct usernames", "users>=5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// 5 failures x 5 users scores 20; 12 failures x 1 user scores 15, so stuffing ranks first.
	i77 := strings.Index(out, "203.0.113.77")
	i23 := strings.Index(out, "198.51.100.23")
	if i77 < 0 || i23 < 0 || i77 > i23 {
		t.Errorf("ranking wrong:\n%s", out)
	}
}

func TestWriteTextNoFlagsAndAcceptedWarning(t *testing.T) {
	var b strings.Builder
	if err := WriteText(&b, Summary{Config: DefaultConfig()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No IPs flagged.") {
		t.Errorf("got:\n%s", b.String())
	}

	var evs []Event
	for i := 0; i < 10; i++ {
		evs = append(evs, failed("198.51.100.23", "root", time.Duration(i)*time.Second, i))
	}
	evs = append(evs, Event{Time: t0.Add(time.Minute), Kind: Accepted, User: "root", IP: netip.MustParseAddr("198.51.100.23"), Port: 99})
	b.Reset()
	if err := WriteText(&b, Summary{Config: DefaultConfig(), Reports: Analyze(evs, DefaultConfig())}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "WARNING: flagged IP 198.51.100.23 also has 1 accepted login(s)") {
		t.Errorf("missing accepted-login warning:\n%s", b.String())
	}
}

func TestSafeUserAndUserList(t *testing.T) {
	cases := map[string]string{
		"root":         "root",
		"":             "(empty)",
		"evil\x1b[31m": `"evil\x1b[31m"`,
		"has space":    `"has space"`,
		"a,b":          `"a,b"`,
	}
	for in, want := range cases {
		if got := safeUser(in); got != want {
			t.Errorf("safeUser(%q) = %s, want %s", in, got, want)
		}
	}
	got := userList([]string{"a", "b", "c", "d", "e", "f", "g", "h"})
	if got != "a,b,c,d,e,f,+2 more" {
		t.Errorf("userList = %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	s := blocklistFixture()
	s.Inputs = []string{"(stdin)"}
	s.Stats = ParseStats{Lines: 40, Events: 38, Ignored: 1, Malformed: 1}
	var b strings.Builder
	if err := WriteJSON(&b, s); err != nil {
		t.Fatal(err)
	}
	var got jsonReport
	if err := json.Unmarshal([]byte(b.String()), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	if got.FlaggedCount != 3 || len(got.IPs) != 5 || got.Malformed != 1 || got.WindowSeconds != 3600 || got.ScoreThreshold != 25 {
		t.Errorf("unexpected header: %+v", got)
	}
	first := got.IPs[0]
	if first.Rank != 1 || first.IP != "203.0.113.77" || !first.Flagged || first.Score != 20 || first.DistinctUsers != 5 {
		t.Errorf("first entry = %+v", first)
	}
	last := got.IPs[len(got.IPs)-1]
	if last.Flagged || last.Reasons == nil || len(last.Reasons) != 0 {
		t.Errorf("unflagged entry should have empty reasons array: %+v", last)
	}
	if !strings.Contains(b.String(), `"failures>=10"`) {
		t.Error("reasons should not be HTML-escaped")
	}
}
