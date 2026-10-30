package main

import (
	"net/netip"
	"sort"
	"strconv"
	"time"
)

// ScoreThreshold is the fixed score at or above which an IP is flagged.
const ScoreThreshold = 25

// UserWeight is the multiplier applied to distinct usernames in the score.
const UserWeight = 3

// Config holds the detection parameters.
type Config struct {
	Window    time.Duration // sliding window length
	Threshold int           // flag when failures in window >= Threshold
	MinUsers  int           // flag when distinct usernames in window >= MinUsers
}

// DefaultConfig matches the CLI defaults.
func DefaultConfig() Config {
	return Config{Window: 60 * time.Minute, Threshold: 10, MinUsers: 5}
}

// IPReport summarises one source IP. Failures, DistinctUsers, Usernames,
// FirstSeen, LastSeen and Score describe the worst (highest-scoring) window
// for that IP; the Total*/Accepted/PreauthClosed fields cover the whole input.
type IPReport struct {
	IP            netip.Addr
	Failures      int
	DistinctUsers int
	Usernames     []string
	FirstSeen     time.Time
	LastSeen      time.Time
	Score         int
	Flagged       bool
	Reasons       []string
	TotalFailures int
	Accepted      int
	PreauthClosed int
}

// Score is the transparent ranking formula: failures + 3 x distinct usernames.
func Score(failures, distinctUsers int) int {
	return failures + UserWeight*distinctUsers
}

// FlagReasons returns which rules a window trips; an empty result means not flagged.
func FlagReasons(cfg Config, failures, distinctUsers int) []string {
	var r []string
	if failures >= cfg.Threshold {
		r = append(r, "failures>="+strconv.Itoa(cfg.Threshold))
	}
	if distinctUsers >= cfg.MinUsers {
		r = append(r, "users>="+strconv.Itoa(cfg.MinUsers))
	}
	if Score(failures, distinctUsers) >= ScoreThreshold {
		r = append(r, "score>="+strconv.Itoa(ScoreThreshold))
	}
	return r
}

// dedupeSpan is how close in time an "Invalid user" line and a "Failed ...
// for invalid user" line on the same IP and source port must be to count as
// the same attempt. sshd's default LoginGraceTime is 2 minutes.
const dedupeSpan = 10 * time.Minute

type connKey struct {
	ip   netip.Addr
	port int
}

// failureEvents returns the events that count as failed attempts:
// every "Failed password/publickey" line, plus "Invalid user" lines that were
// NOT followed by a Failed line on the same connection (same IP and source
// port). sshd usually logs both lines for one attempt; counting both would
// double the failure count.
func failureEvents(events []Event) []Event {
	failedAt := map[connKey][]time.Time{}
	for _, e := range events {
		if e.Kind == FailedPassword || e.Kind == FailedPublickey {
			k := connKey{e.IP, e.Port}
			failedAt[k] = append(failedAt[k], e.Time)
		}
	}
	var out []Event
	for _, e := range events {
		switch e.Kind {
		case FailedPassword, FailedPublickey:
			out = append(out, e)
		case InvalidUser:
			covered := false
			for _, t := range failedAt[connKey{e.IP, e.Port}] {
				if d := t.Sub(e.Time); d >= -dedupeSpan && d <= dedupeSpan {
					covered = true
					break
				}
			}
			if !covered {
				out = append(out, e)
			}
		}
	}
	return out
}

// Analyze groups events by source IP and evaluates every sliding window of
// length cfg.Window (window span = last - first <= cfg.Window). It returns one
// IPReport per IP that has at least one failure, ranked worst score first.
func Analyze(events []Event, cfg Config) []IPReport {
	byIP := map[netip.Addr][]Event{}
	accepted := map[netip.Addr]int{}
	closed := map[netip.Addr]int{}
	for _, e := range failureEvents(events) {
		byIP[e.IP] = append(byIP[e.IP], e)
	}
	for _, e := range events {
		switch e.Kind {
		case Accepted:
			accepted[e.IP]++
		case PreauthClose:
			closed[e.IP]++
		}
	}

	reports := make([]IPReport, 0, len(byIP))
	for ip, evs := range byIP {
		r := worstWindow(evs, cfg)
		r.IP = ip
		r.TotalFailures = len(evs)
		r.Accepted = accepted[ip]
		r.PreauthClosed = closed[ip]
		r.Reasons = FlagReasons(cfg, r.Failures, r.DistinctUsers)
		r.Flagged = len(r.Reasons) > 0
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool {
		a, b := reports[i], reports[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Failures != b.Failures {
			return a.Failures > b.Failures
		}
		return a.IP.Less(b.IP)
	})
	return reports
}

// worstWindow slides a window over one IP's failure events and returns the
// worst one: the highest-scoring window that trips a flag rule, or the
// highest-scoring window overall if none does (earliest wins ties). Preferring
// flagged windows matters because a window with many failures for one user can
// score lower than a short window with a few users yet still trip --threshold.
func worstWindow(evs []Event, cfg Config) IPReport {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })

	users := map[string]int{}
	var best IPReport
	bestFlagged := false
	bestL, bestR := -1, -1
	left := 0
	for right, e := range evs {
		users[e.User]++
		for e.Time.Sub(evs[left].Time) > cfg.Window {
			u := evs[left].User
			if users[u]--; users[u] == 0 {
				delete(users, u)
			}
			left++
		}
		failures := right - left + 1
		score := Score(failures, len(users))
		flagged := len(FlagReasons(cfg, failures, len(users))) > 0
		if bestL < 0 || (flagged && !bestFlagged) || (flagged == bestFlagged && score > best.Score) {
			bestFlagged = flagged
			best = IPReport{
				Failures:      failures,
				DistinctUsers: len(users),
				Score:         score,
				FirstSeen:     evs[left].Time,
				LastSeen:      e.Time,
			}
			bestL, bestR = left, right
		}
	}
	if bestL >= 0 {
		seen := map[string]bool{}
		for _, e := range evs[bestL : bestR+1] {
			if !seen[e.User] {
				seen[e.User] = true
				best.Usernames = append(best.Usernames, e.User)
			}
		}
		sort.Strings(best.Usernames)
	}
	return best
}

// Flagged returns only the flagged reports, preserving order.
func Flagged(reports []IPReport) []IPReport {
	var out []IPReport
	for _, r := range reports {
		if r.Flagged {
			out = append(out, r)
		}
	}
	return out
}
