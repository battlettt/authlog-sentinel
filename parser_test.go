package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testParser() *Parser {
	return &Parser{Now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), Loc: time.UTC}
}

func TestParseLineShapes(t *testing.T) {
	ts := time.Date(2026, 10, 28, 3, 12, 45, 0, time.UTC)
	tests := []struct {
		name    string
		line    string
		kind    EventKind
		user    string
		invalid bool
		ip      string
		port    int
		method  string
	}{
		{"failed password", "Oct 28 03:12:45 host sshd[100]: Failed password for root from 198.51.100.23 port 51122 ssh2",
			FailedPassword, "root", false, "198.51.100.23", 51122, "password"},
		{"failed password invalid user", "Oct 28 03:12:45 host sshd[100]: Failed password for invalid user admin from 203.0.113.77 port 40000 ssh2",
			FailedPassword, "admin", true, "203.0.113.77", 40000, "password"},
		{"failed publickey with key suffix", "Oct 28 03:12:45 host sshd[100]: Failed publickey for git from 203.0.113.5 port 2222 ssh2: RSA SHA256:abc",
			FailedPublickey, "git", false, "203.0.113.5", 2222, "publickey"},
		{"failed publickey invalid user", "Oct 28 03:12:45 host sshd[100]: Failed publickey for invalid user jenkins from 203.0.113.5 port 2223 ssh2",
			FailedPublickey, "jenkins", true, "203.0.113.5", 2223, "publickey"},
		{"invalid user", "Oct 28 03:12:45 host sshd[100]: Invalid user oracle from 203.0.113.77 port 33809",
			InvalidUser, "oracle", true, "203.0.113.77", 33809, ""},
		{"invalid user empty name", "Oct 28 03:12:45 host sshd[100]: Invalid user  from 203.0.113.9 port 1234",
			InvalidUser, "", true, "203.0.113.9", 1234, ""},
		{"invalid user with spaces", "Oct 28 03:12:45 host sshd[100]: Invalid user bob from mars from 203.0.113.9 port 1235",
			InvalidUser, "bob from mars", true, "203.0.113.9", 1235, ""},
		{"preauth close", "Oct 28 03:12:45 host sshd[100]: Connection closed by 192.0.2.200 port 5555 [preauth]",
			PreauthClose, "", false, "192.0.2.200", 5555, ""},
		{"accepted password", "Oct 28 03:12:45 host sshd[100]: Accepted password for alice from 192.0.2.11 port 6000 ssh2",
			Accepted, "alice", false, "192.0.2.11", 6000, "password"},
		{"accepted publickey", "Oct 28 03:12:45 host sshd[100]: Accepted publickey for deploy from 192.0.2.10 port 6001 ssh2: ED25519 SHA256:xyz",
			Accepted, "deploy", false, "192.0.2.10", 6001, "publickey"},
		{"ipv6", "Oct 28 03:12:45 host sshd[100]: Failed password for alice from 2001:db8::7 port 7 ssh2",
			FailedPassword, "alice", false, "2001:db8::7", 7, "password"},
		{"sshd-session program", "Oct 28 03:12:45 host sshd-session[100]: Failed password for root from 198.51.100.1 port 9 ssh2",
			FailedPassword, "root", false, "198.51.100.1", 9, "password"},
		{"no pid", "Oct 28 03:12:45 host sshd: Failed password for root from 198.51.100.1 port 9 ssh2",
			FailedPassword, "root", false, "198.51.100.1", 9, "password"},
	}
	p := testParser()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := p.ParseLine(tc.line)
			if err != nil {
				t.Fatalf("ParseLine error: %v", err)
			}
			if ev.Kind != tc.kind || ev.User != tc.user || ev.InvalidUser != tc.invalid ||
				ev.IP != netip.MustParseAddr(tc.ip) || ev.Port != tc.port || ev.Method != tc.method {
				t.Errorf("got %+v (kind %s)", ev, ev.Kind)
			}
			if !ev.Time.Equal(ts) {
				t.Errorf("time = %v, want %v", ev.Time, ts)
			}
		})
	}
}

func TestParseRFC3339Timestamp(t *testing.T) {
	ev, err := testParser().ParseLine("2025-03-01T10:20:30.123456+02:00 host sshd[5]: Failed password for root from 198.51.100.9 port 22 ssh2")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 3, 1, 8, 20, 30, 123456000, time.UTC)
	if !ev.Time.Equal(want) {
		t.Errorf("time = %v, want %v", ev.Time, want)
	}
}

func TestParseSingleDigitDay(t *testing.T) {
	ev, err := testParser().ParseLine("Oct  8 01:02:03 host sshd[5]: Invalid user x from 198.51.100.9 port 22")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Time.Day() != 8 || ev.Time.Year() != 2026 {
		t.Errorf("time = %v", ev.Time)
	}
}

func TestParseYearRollover(t *testing.T) {
	p := &Parser{Now: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Loc: time.UTC}
	ev, err := p.ParseLine("Dec 31 23:59:59 host sshd[5]: Invalid user x from 198.51.100.9 port 22")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Time.Year() != 2025 {
		t.Errorf("year = %d, want 2025", ev.Time.Year())
	}
}

func TestParseLineIgnoredAndMalformed(t *testing.T) {
	ignored := []string{
		"Oct 28 03:12:45 host CRON[1]: pam_unix(cron:session): session opened for user root",
		"Oct 28 03:12:45 host sshd[1]: Server listening on 0.0.0.0 port 22.",
		"Oct 28 03:12:45 host sshd[1]: Received disconnect from 198.51.100.23 port 51122:11: Bye Bye [preauth]",
		"Oct 28 03:12:45 host sshd[1]: Failed none for root from 198.51.100.23 port 1 ssh2",
		"Oct 28 03:12:45 host sshd[1]: Connection closed by 198.51.100.23 port 1",
		"Oct 28 03:12:45 host sshd[1]: Accepted keyboard-interactive/pam for root from 198.51.100.23 port 1 ssh2",
	}
	malformed := []string{
		"Oct 28 03:1",
		"<garbage>",
		"Oct 28 25:61:99 host sshd[1]: Failed password for root from 198.51.100.23 port 1 ssh2",
		"Oct 28 03:12:45 host sshd[1]: Failed password for root from 999.1.2.3 port 22 ssh2",
		"Oct 28 03:12:45 host sshd[1]: Failed password for root from host.example port 22 ssh2",
		"Oct 28 03:12:45 host sshd[1]: Invalid user x from 198.51.100.1 port 99999",
		"Oct 28 03:12:45 hostonly",
		"2026-99-99T00:00:00Z host sshd[1]: Invalid user x from 198.51.100.1 port 1",
	}
	p := testParser()
	for _, l := range ignored {
		if _, err := p.ParseLine(l); err != errIgnored {
			t.Errorf("%q: err = %v, want errIgnored", l, err)
		}
	}
	for _, l := range malformed {
		if _, err := p.ParseLine(l); err == nil || err == errIgnored {
			t.Errorf("%q: err = %v, want malformed error", l, err)
		}
	}
}

func TestParseCountsAndSkips(t *testing.T) {
	input := strings.Join([]string{
		"# SYNTHETIC header comment",
		"",
		"Oct 28 03:00:00 host sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2",
		"Oct 28 03:00:01 host sshd[1]: Invalid user bob from 198.51.100.1 port 2",
		"garbage line",
		"Oct 28 03:00:0",
		"Oct 28 03:00:02 host CRON[2]: something else",
		"Oct 28 03:00:03 host sshd[1]: Connection closed by 198.51.100.1 port 2 [preauth]\r",
		strings.Repeat("x", maxLineLen+1),
		"Oct 28 03:00:04 host sshd[1]: Accepted password for alice from 192.0.2.1 port 3 ssh2", // no trailing newline
	}, "\n")
	evs, st, err := testParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := ParseStats{Lines: 8, Events: 4, Ignored: 1, Malformed: 3}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	if len(evs) != 4 {
		t.Fatalf("got %d events, want 4", len(evs))
	}
	if evs[2].Kind != PreauthClose || evs[3].Kind != Accepted {
		t.Errorf("unexpected kinds: %v %v", evs[2].Kind, evs[3].Kind)
	}
}

func TestParseStatsAdd(t *testing.T) {
	a := ParseStats{1, 2, 3, 4}
	a.Add(ParseStats{10, 20, 30, 40})
	if a != (ParseStats{11, 22, 33, 44}) {
		t.Errorf("Add = %+v", a)
	}
}

func TestEventKindString(t *testing.T) {
	for k, want := range map[EventKind]string{
		FailedPassword: "failed-password", FailedPublickey: "failed-publickey", InvalidUser: "invalid-user",
		PreauthClose: "preauth-close", Accepted: "accepted", EventKind(99): "unknown",
	} {
		if k.String() != want {
			t.Errorf("%d.String() = %q, want %q", k, k.String(), want)
		}
	}
}
