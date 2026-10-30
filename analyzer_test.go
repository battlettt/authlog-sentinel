package main

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)

func failed(ip, user string, at time.Duration, port int) Event {
	return Event{Time: t0.Add(at), Kind: FailedPassword, User: user, IP: netip.MustParseAddr(ip), Port: port, Method: "password"}
}

func findIP(t *testing.T, rs []IPReport, ip string) IPReport {
	t.Helper()
	for _, r := range rs {
		if r.IP == netip.MustParseAddr(ip) {
			return r
		}
	}
	t.Fatalf("no report for %s", ip)
	return IPReport{}
}

func TestScore(t *testing.T) {
	cases := []struct{ f, u, want int }{{0, 0, 0}, {10, 1, 13}, {12, 12, 48}, {25, 1, 28}, {1, 8, 25}}
	for _, c := range cases {
		if got := Score(c.f, c.u); got != c.want {
			t.Errorf("Score(%d,%d) = %d, want %d", c.f, c.u, got, c.want)
		}
	}
}

func TestFlagReasons(t *testing.T) {
	cfg := DefaultConfig()
	cases := []struct {
		f, u int
		want []string
	}{
		{9, 1, nil},                                    // score 12
		{10, 1, []string{"failures>=10"}},              // threshold boundary
		{4, 5, []string{"users>=5"}},                   // min-users boundary, score 19
		{4, 4, nil},                                    // score 16
		{9, 4, nil},                                    // score 21
		{1, 8, []string{"users>=5", "score>=25"}},      // score exactly 25
		{22, 1, []string{"failures>=10", "score>=25"}}, // score 25
		{12, 12, []string{"failures>=10", "users>=5", "score>=25"}},
	}
	for _, c := range cases {
		if got := FlagReasons(cfg, c.f, c.u); !reflect.DeepEqual(got, c.want) {
			t.Errorf("FlagReasons(%d,%d) = %v, want %v", c.f, c.u, got, c.want)
		}
	}
	// score rule alone: raise the other thresholds out of reach.
	high := Config{Window: time.Hour, Threshold: 100, MinUsers: 100}
	if got := FlagReasons(high, 7, 6); !reflect.DeepEqual(got, []string{"score>=25"}) {
		t.Errorf("score-only rule = %v", got)
	}
}

func TestAnalyzeScoringAndUsers(t *testing.T) {
	var evs []Event
	users := []string{"admin", "test", "oracle", "admin", "pi"}
	for i, u := range users {
		evs = append(evs, failed("203.0.113.77", u, time.Duration(i)*time.Minute, 1000+i))
	}
	rs := Analyze(evs, DefaultConfig())
	if len(rs) != 1 {
		t.Fatalf("got %d reports", len(rs))
	}
	r := rs[0]
	if r.Failures != 5 || r.DistinctUsers != 4 || r.Score != 17 || r.Flagged {
		t.Errorf("got failures=%d users=%d score=%d flagged=%v", r.Failures, r.DistinctUsers, r.Score, r.Flagged)
	}
	if !reflect.DeepEqual(r.Usernames, []string{"admin", "oracle", "pi", "test"}) {
		t.Errorf("usernames = %v", r.Usernames)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(4*time.Minute)) {
		t.Errorf("first/last = %v / %v", r.FirstSeen, r.LastSeen)
	}
}

func TestAnalyzeWindowExcludesDistantEvents(t *testing.T) {
	// 6 failures, then 6 more two hours later: never 10 inside one 60m window.
	var evs []Event
	for i := 0; i < 6; i++ {
		evs = append(evs, failed("198.51.100.1", "root", time.Duration(i)*time.Minute, i))
		evs = append(evs, failed("198.51.100.1", "root", 2*time.Hour+time.Duration(i)*time.Minute, 100+i))
	}
	r := Analyze(evs, DefaultConfig())[0]
	if r.Failures != 6 || r.TotalFailures != 12 || r.Flagged {
		t.Errorf("60m window: failures=%d total=%d flagged=%v", r.Failures, r.TotalFailures, r.Flagged)
	}
	// A 3h window covers both bursts.
	cfg := DefaultConfig()
	cfg.Window = 3 * time.Hour
	r = Analyze(evs, cfg)[0]
	if r.Failures != 12 || !r.Flagged {
		t.Errorf("3h window: failures=%d flagged=%v", r.Failures, r.Flagged)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(2*time.Hour+5*time.Minute)) {
		t.Errorf("first/last = %v / %v", r.FirstSeen, r.LastSeen)
	}
}

func TestAnalyzeWindowBoundaryInclusive(t *testing.T) {
	// Span exactly == window: all three events share a window.
	evs := []Event{
		failed("198.51.100.1", "root", 0, 1),
		failed("198.51.100.1", "root", 30*time.Minute, 2),
		failed("198.51.100.1", "root", 60*time.Minute, 3),
	}
	if r := Analyze(evs, DefaultConfig())[0]; r.Failures != 3 {
		t.Errorf("span == window: failures = %d, want 3", r.Failures)
	}
	// One second past the window: the first event falls out.
	evs[2] = failed("198.51.100.1", "root", 60*time.Minute+time.Second, 3)
	if r := Analyze(evs, DefaultConfig())[0]; r.Failures != 2 {
		t.Errorf("span > window: failures = %d, want 2", r.Failures)
	}
}

func TestAnalyzeSlidingWindowDropsOldUsers(t *testing.T) {
	// Users a,b,c early; users d,e,f 90 min later. No 60m window has more than 3 users.
	var evs []Event
	for i, u := range []string{"a", "b", "c"} {
		evs = append(evs, failed("198.51.100.2", u, time.Duration(i)*time.Minute, i))
	}
	for i, u := range []string{"d", "e", "f"} {
		evs = append(evs, failed("198.51.100.2", u, 90*time.Minute+time.Duration(i)*time.Minute, 10+i))
	}
	r := Analyze(evs, DefaultConfig())[0]
	if r.DistinctUsers != 3 || r.Flagged {
		t.Errorf("users=%d flagged=%v", r.DistinctUsers, r.Flagged)
	}
}

func TestAnalyzeUnsortedInput(t *testing.T) {
	evs := []Event{
		failed("198.51.100.3", "root", 30*time.Minute, 1),
		failed("198.51.100.3", "root", 0, 2),
		failed("198.51.100.3", "root", 10*time.Minute, 3),
	}
	r := Analyze(evs, DefaultConfig())[0]
	if r.Failures != 3 || !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("got %+v", r)
	}
}

func TestAnalyzePrefersFlaggedWindow(t *testing.T) {
	// Burst A: 10 failures for root over 50 min (score 13, trips threshold).
	// Burst B, 3h later: 1 failure each for 4 users (score 16, trips nothing).
	cfg := DefaultConfig()
	var evs []Event
	for i := 0; i < 10; i++ {
		evs = append(evs, failed("198.51.100.4", "root", time.Duration(i)*5*time.Minute, i))
	}
	for i, u := range []string{"a", "b", "c", "d"} {
		evs = append(evs, failed("198.51.100.4", u, 3*time.Hour+time.Duration(i)*time.Minute, 100+i))
	}
	r := Analyze(evs, cfg)[0]
	if !r.Flagged || r.Failures != 10 || r.Score != 13 {
		t.Errorf("flagged=%v failures=%d score=%d", r.Flagged, r.Failures, r.Score)
	}
}

func TestAnalyzeInvalidUserDedupe(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	evs := []Event{
		// Same connection: Invalid user + Failed => one attempt.
		{Time: t0, Kind: InvalidUser, User: "admin", InvalidUser: true, IP: ip, Port: 100},
		{Time: t0.Add(2 * time.Second), Kind: FailedPassword, User: "admin", InvalidUser: true, IP: ip, Port: 100},
		// Invalid user with no Failed line => counted on its own.
		{Time: t0.Add(time.Minute), Kind: InvalidUser, User: "", InvalidUser: true, IP: ip, Port: 200},
		// Preauth closes and accepted logins are context only.
		{Time: t0.Add(time.Minute), Kind: PreauthClose, IP: ip, Port: 200},
		{Time: t0.Add(2 * time.Minute), Kind: Accepted, User: "bob", IP: ip, Port: 300},
	}
	r := Analyze(evs, DefaultConfig())[0]
	if r.Failures != 2 || r.DistinctUsers != 2 || r.PreauthClosed != 1 || r.Accepted != 1 {
		t.Errorf("got failures=%d users=%d preauth=%d accepted=%d", r.Failures, r.DistinctUsers, r.PreauthClosed, r.Accepted)
	}
	if !reflect.DeepEqual(r.Usernames, []string{"", "admin"}) {
		t.Errorf("usernames = %q", r.Usernames)
	}
}

func TestAnalyzeInvalidUserSamePortFarApartNotDeduped(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	evs := []Event{
		{Time: t0, Kind: InvalidUser, User: "x", IP: ip, Port: 100},
		{Time: t0.Add(30 * time.Minute), Kind: FailedPassword, User: "y", IP: ip, Port: 100},
	}
	if r := Analyze(evs, DefaultConfig())[0]; r.Failures != 2 {
		t.Errorf("failures = %d, want 2", r.Failures)
	}
}

func TestAnalyzeContextOnlyIPsNotReported(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.200")
	evs := []Event{
		{Time: t0, Kind: PreauthClose, IP: ip, Port: 1},
		{Time: t0, Kind: Accepted, User: "deploy", IP: netip.MustParseAddr("192.0.2.10"), Port: 2},
	}
	if rs := Analyze(evs, DefaultConfig()); len(rs) != 0 {
		t.Errorf("expected no reports, got %+v", rs)
	}
}

func TestAnalyzeRankingAndFlagged(t *testing.T) {
	var evs []Event
	// stuffing: 6 users => 6 + 18 = 24, flagged by users.
	for i, u := range []string{"a", "b", "c", "d", "e", "f"} {
		evs = append(evs, failed("203.0.113.1", u, time.Duration(i)*time.Second, i))
	}
	// brute: 25 x root => 28.
	for i := 0; i < 25; i++ {
		evs = append(evs, failed("198.51.100.1", "root", time.Duration(i)*time.Second, 100+i))
	}
	// noise: 2 x alice => 5, not flagged.
	evs = append(evs, failed("192.0.2.5", "alice", 0, 500), failed("192.0.2.5", "alice", time.Minute, 501))
	// tie with noise score, lower IP sorts first.
	evs = append(evs, failed("192.0.2.4", "bob", 0, 600), failed("192.0.2.4", "bob", time.Minute, 601))

	rs := Analyze(evs, DefaultConfig())
	var order []string
	for _, r := range rs {
		order = append(order, r.IP.String())
	}
	want := []string{"198.51.100.1", "203.0.113.1", "192.0.2.4", "192.0.2.5"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	fl := Flagged(rs)
	if len(fl) != 2 || fl[0].IP.String() != "198.51.100.1" || fl[1].IP.String() != "203.0.113.1" {
		t.Errorf("flagged = %v", fl)
	}
	if r := findIP(t, rs, "203.0.113.1"); !reflect.DeepEqual(r.Reasons, []string{"users>=5"}) {
		t.Errorf("reasons = %v", r.Reasons)
	}
}

func TestAnalyzeCustomThresholds(t *testing.T) {
	var evs []Event
	for i := 0; i < 3; i++ {
		evs = append(evs, failed("198.51.100.7", "root", time.Duration(i)*time.Minute, i))
	}
	cfg := Config{Window: 30 * time.Minute, Threshold: 3, MinUsers: 5}
	if r := Analyze(evs, cfg)[0]; !r.Flagged {
		t.Error("expected flag with --threshold 3")
	}
	cfg = Config{Window: 30 * time.Minute, Threshold: 10, MinUsers: 1}
	if r := Analyze(evs, cfg)[0]; !reflect.DeepEqual(r.Reasons, []string{"users>=1"}) {
		t.Errorf("reasons = %v", r.Reasons)
	}
}
