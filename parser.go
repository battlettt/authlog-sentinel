package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EventKind identifies which sshd message shape a line matched.
type EventKind int

const (
	FailedPassword  EventKind = iota // Failed password for [invalid user] USER from IP port N ssh2
	FailedPublickey                  // Failed publickey for [invalid user] USER from IP port N ssh2
	InvalidUser                      // Invalid user USER from IP port N
	PreauthClose                     // Connection closed by IP port N [preauth]
	Accepted                         // Accepted password|publickey for USER from IP port N ssh2
)

func (k EventKind) String() string {
	switch k {
	case FailedPassword:
		return "failed-password"
	case FailedPublickey:
		return "failed-publickey"
	case InvalidUser:
		return "invalid-user"
	case PreauthClose:
		return "preauth-close"
	case Accepted:
		return "accepted"
	}
	return "unknown"
}

// Event is one recognized sshd authentication event.
type Event struct {
	Time        time.Time
	Kind        EventKind
	User        string // empty for PreauthClose; may legitimately be empty for InvalidUser
	InvalidUser bool   // "for invalid user ..." form of a Failed line
	IP          netip.Addr
	Port        int
	Method      string // "password" or "publickey" for Failed/Accepted lines
}

// ParseStats counts what happened to every input line.
type ParseStats struct {
	Lines     int // all lines read, excluding blank and '#' comment lines
	Events    int // lines that produced an Event
	Ignored   int // well-formed syslog lines that are not a recognized sshd auth event
	Malformed int // lines that are not parseable syslog, or sshd lines with a bad IP/port
}

func (s *ParseStats) Add(o ParseStats) {
	s.Lines += o.Lines
	s.Events += o.Events
	s.Ignored += o.Ignored
	s.Malformed += o.Malformed
}

var (
	reFailed  = regexp.MustCompile(`^Failed (password|publickey) for (invalid user )?(.*) from (\S+) port (\d+) ssh2(?::.*)?$`)
	reInvalid = regexp.MustCompile(`^Invalid user (.*) from (\S+) port (\d+)$`)
	reClosed  = regexp.MustCompile(`^Connection closed by (\S+) port (\d+) \[preauth\]$`)
	reAccept  = regexp.MustCompile(`^Accepted (password|publickey) for (.*) from (\S+) port (\d+) ssh2(?::.*)?$`)
)

// Parser turns syslog lines into Events.
//
// Traditional syslog timestamps ("Oct 28 03:12:45") carry no year. The parser
// assumes the year of Now; if that would put the event more than two days in
// the future, it uses the previous year instead (handles logs from December
// read in January). RFC 3339 timestamps (rsyslog high-precision format) are
// used as-is.
type Parser struct {
	Now time.Time
	Loc *time.Location
}

// NewParser returns a Parser using the current time and local time zone.
func NewParser() *Parser {
	return &Parser{Now: time.Now(), Loc: time.Local}
}

// errIgnored marks a well-formed syslog line that is not an sshd auth event.
var errIgnored = errors.New("not a recognized sshd auth event")

// ParseLine parses one line. It returns errIgnored for valid syslog lines that
// carry no relevant sshd event, and another error for malformed lines.
func (p *Parser) ParseLine(line string) (Event, error) {
	ts, rest, err := p.parseTimestamp(line)
	if err != nil {
		return Event{}, err
	}
	// rest: "host prog[pid]: message"
	host, rest, ok := strings.Cut(rest, " ")
	if !ok || host == "" {
		return Event{}, fmt.Errorf("missing hostname")
	}
	tag, msg, ok := strings.Cut(rest, ": ")
	if !ok {
		return Event{}, fmt.Errorf("missing program tag")
	}
	prog := tag
	if i := strings.IndexByte(tag, '['); i >= 0 {
		prog = tag[:i]
	}
	if prog != "sshd" && prog != "sshd-session" {
		return Event{}, errIgnored
	}
	msg = strings.TrimRight(msg, " \r")

	ev := Event{Time: ts}
	var ipStr, portStr string
	switch {
	case strings.HasPrefix(msg, "Failed "):
		m := reFailed.FindStringSubmatch(msg)
		if m == nil {
			return Event{}, errIgnored // e.g. "Failed none for ..."
		}
		ev.Kind = FailedPassword
		if m[1] == "publickey" {
			ev.Kind = FailedPublickey
		}
		ev.Method, ev.InvalidUser, ev.User = m[1], m[2] != "", m[3]
		ipStr, portStr = m[4], m[5]
	case strings.HasPrefix(msg, "Invalid user "):
		m := reInvalid.FindStringSubmatch(msg)
		if m == nil {
			return Event{}, errIgnored
		}
		ev.Kind, ev.User, ev.InvalidUser = InvalidUser, m[1], true
		ipStr, portStr = m[2], m[3]
	case strings.HasPrefix(msg, "Connection closed by "):
		m := reClosed.FindStringSubmatch(msg)
		if m == nil {
			return Event{}, errIgnored // closes after auth, or newer "by invalid user" forms
		}
		ev.Kind = PreauthClose
		ipStr, portStr = m[1], m[2]
	case strings.HasPrefix(msg, "Accepted "):
		m := reAccept.FindStringSubmatch(msg)
		if m == nil {
			return Event{}, errIgnored
		}
		ev.Kind, ev.Method, ev.User = Accepted, m[1], m[2]
		ipStr, portStr = m[3], m[4]
	default:
		return Event{}, errIgnored
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return Event{}, fmt.Errorf("bad IP %q", ipStr)
	}
	ev.IP = ip.Unmap()
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return Event{}, fmt.Errorf("bad port %q", portStr)
	}
	ev.Port = port
	return ev, nil
}

func (p *Parser) parseTimestamp(line string) (time.Time, string, error) {
	loc := p.Loc
	if loc == nil {
		loc = time.Local
	}
	// RFC 3339, e.g. "2026-10-28T03:12:45.123456+00:00 host sshd[1]: ..."
	if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
		field, rest, ok := strings.Cut(line, " ")
		if !ok {
			return time.Time{}, "", fmt.Errorf("truncated line")
		}
		t, err := time.Parse(time.RFC3339Nano, field)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("bad timestamp %q", field)
		}
		return t, rest, nil
	}
	// Traditional BSD syslog, e.g. "Oct 28 03:12:45 host ..." or "Oct  8 03:12:45 host ...".
	const layout = "Jan _2 15:04:05"
	if len(line) < len(layout)+1 || line[len(layout)] != ' ' {
		return time.Time{}, "", fmt.Errorf("truncated or malformed timestamp")
	}
	t, err := time.ParseInLocation(layout, line[:len(layout)], loc)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("bad timestamp %q", line[:len(layout)])
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
	if t.After(now.Add(48 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, line[len(layout)+1:], nil
}

// Parse reads every line from r. Blank lines and lines starting with '#' are
// skipped silently; unrecognized and malformed lines are counted, never fatal.
func (p *Parser) Parse(r io.Reader) ([]Event, ParseStats, error) {
	var events []Event
	var st ParseStats
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadString('\n')
		if line != "" {
			p.parseInto(line, &events, &st)
		}
		if readErr == io.EOF {
			return events, st, nil
		}
		if readErr != nil {
			return events, st, readErr
		}
	}
}

// maxLineLen bounds a single log line; longer lines are counted as malformed.
const maxLineLen = 64 * 1024

func (p *Parser) parseInto(line string, events *[]Event, st *ParseStats) {
	line = strings.TrimRight(line, "\r\n")
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return
	}
	st.Lines++
	if len(line) > maxLineLen {
		st.Malformed++
		return
	}
	ev, err := p.ParseLine(line)
	switch {
	case err == nil:
		st.Events++
		*events = append(*events, ev)
	case errors.Is(err, errIgnored):
		st.Ignored++
	default:
		st.Malformed++
	}
}
