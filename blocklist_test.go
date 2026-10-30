package main

import (
	"strings"
	"testing"
	"time"
)

func blocklistFixture() Summary {
	var evs []Event
	for i := 0; i < 12; i++ {
		evs = append(evs, failed("198.51.100.23", "root", time.Duration(i)*time.Minute, i))
		evs = append(evs, failed("2001:db8::bad", "alice", time.Duration(i)*time.Minute, 100+i))
	}
	for i, u := range []string{"a", "b", "c", "d", "e"} {
		evs = append(evs, failed("203.0.113.77", u, time.Duration(i)*time.Minute, 200+i))
	}
	// Below threshold.
	evs = append(evs, failed("192.0.2.11", "alice", 0, 300), failed("203.0.113.5", "git", 0, 301))
	cfg := DefaultConfig()
	return Summary{Config: cfg, Reports: Analyze(evs, cfg)}
}

func TestBlocklistContainsOnlyFlagged(t *testing.T) {
	var b strings.Builder
	if err := WriteBlocklist(&b, blocklistFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, ip := range []string{"198.51.100.23", "2001:db8::bad", "203.0.113.77"} {
		if !strings.Contains(out, "\n"+ip+"\n") {
			t.Errorf("flagged IP %s missing from list", ip)
		}
		if !strings.Contains(out, ip+" ") && !strings.Contains(out, ip+",") {
			t.Errorf("flagged IP %s missing from rules", ip)
		}
	}
	for _, ip := range []string{"192.0.2.11", "203.0.113.5"} {
		if strings.Contains(out, ip) {
			t.Errorf("unflagged IP %s present in blocklist", ip)
		}
	}
	if !strings.Contains(out, "ip6tables -I INPUT -s 2001:db8::bad") || !strings.Contains(out, "ip6 saddr { 2001:db8::bad }") {
		t.Error("IPv6 rules missing")
	}
	if strings.Contains(out, "iptables -I INPUT -s 2001:db8::bad") && !strings.Contains(out, "ip6tables -I INPUT -s 2001:db8::bad") {
		t.Error("IPv6 address used with iptables")
	}
}

func TestBlocklistRulesAreCommented(t *testing.T) {
	var b strings.Builder
	if err := WriteBlocklist(&b, blocklistFixture()); err != nil {
		t.Fatal(err)
	}
	ruleLines := 0
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.Contains(line, "iptables") || strings.Contains(line, "nft ") {
			ruleLines++
			if !strings.HasPrefix(line, "# ") {
				t.Errorf("rule line not commented: %q", line)
			}
		}
		// Every uncommented, non-empty line must be a bare IP.
		if line != "" && !strings.HasPrefix(line, "#") && strings.ContainsAny(line, " \t") {
			t.Errorf("unexpected uncommented content: %q", line)
		}
	}
	if ruleLines < 5 { // 3 iptables/ip6tables + 2 nft
		t.Errorf("expected at least 5 rule lines, got %d", ruleLines)
	}
	if !strings.Contains(b.String(), "Nothing has been blocked") {
		t.Error("missing safety notice")
	}
}

func TestBlocklistEmpty(t *testing.T) {
	var b strings.Builder
	s := Summary{Config: DefaultConfig(), Reports: Analyze([]Event{failed("192.0.2.1", "a", 0, 1)}, DefaultConfig())}
	if err := WriteBlocklist(&b, s); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "192.0.2.1") || strings.Contains(out, "iptables") {
		t.Errorf("empty blocklist should list nothing:\n%s", out)
	}
	if !strings.Contains(out, "No IPs flagged") {
		t.Error("missing empty notice")
	}
}
