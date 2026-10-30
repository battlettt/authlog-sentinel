package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Summary is everything the report writers need.
type Summary struct {
	Inputs  []string
	Stats   ParseStats
	Config  Config
	Reports []IPReport // ranked, all IPs with at least one failure
}

const timeLayout = "2006-01-02 15:04:05"

// maxShownUsers limits how many usernames the text report prints per IP.
const maxShownUsers = 6

// safeUser renders an attacker-controlled username for a terminal: empty
// names are shown as (empty), and anything non-printable is escaped so log
// content cannot inject terminal control sequences.
func safeUser(u string) string {
	if u == "" {
		return "(empty)"
	}
	q := strconv.QuoteToGraphic(u)
	if q[1:len(q)-1] == u && !strings.ContainsAny(u, " ,") {
		return u
	}
	return q
}

func userList(users []string) string {
	shown := users
	if len(shown) > maxShownUsers {
		shown = shown[:maxShownUsers]
	}
	parts := make([]string, len(shown))
	for i, u := range shown {
		parts[i] = safeUser(u)
	}
	s := strings.Join(parts, ",")
	if extra := len(users) - len(shown); extra > 0 {
		s += fmt.Sprintf(",+%d more", extra)
	}
	return s
}

// WriteText writes the human-readable ranked report.
func WriteText(w io.Writer, s Summary) error {
	flagged := Flagged(s.Reports)
	var below []IPReport
	for _, r := range s.Reports {
		if !r.Flagged {
			below = append(below, r)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "AuthLog Sentinel report\n")
	fmt.Fprintf(&b, "Inputs:     %s\n", strings.Join(s.Inputs, ", "))
	fmt.Fprintf(&b, "Lines:      %d read, %d sshd auth events, %d ignored, %d malformed (skipped)\n",
		s.Stats.Lines, s.Stats.Events, s.Stats.Ignored, s.Stats.Malformed)
	fmt.Fprintf(&b, "Window:     %s sliding\n", s.Config.Window)
	fmt.Fprintf(&b, "Flag rule:  failures >= %d OR distinct users >= %d OR score >= %d\n",
		s.Config.Threshold, s.Config.MinUsers, ScoreThreshold)
	fmt.Fprintf(&b, "Score:      failures + %d x distinct usernames (worst window per IP)\n\n", UserWeight)

	if len(flagged) == 0 {
		fmt.Fprintf(&b, "No IPs flagged.\n")
	} else {
		fmt.Fprintf(&b, "FLAGGED IPs (%d), worst first\n", len(flagged))
		writeTable(&b, flagged, true)
	}
	if len(below) > 0 {
		fmt.Fprintf(&b, "\nBelow threshold (%d)\n", len(below))
		writeTable(&b, below, false)
	}
	for _, r := range flagged {
		if r.Accepted > 0 {
			fmt.Fprintf(&b, "\nWARNING: flagged IP %s also has %d accepted login(s); investigate for possible compromise.\n",
				r.IP, r.Accepted)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeTable(w io.Writer, rs []IPReport, withReasons bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "RANK\tIP\tSCORE\tFAILS\tUSERS\tFIRST SEEN\tLAST SEEN\tTOTAL\tPREAUTH\tACCEPTED\tUSERNAMES"
	if withReasons {
		header += "\tREASONS"
	}
	fmt.Fprintln(tw, header)
	for i, r := range rs {
		line := fmt.Sprintf("%d\t%s\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%d\t%s",
			i+1, r.IP, r.Score, r.Failures, r.DistinctUsers,
			r.FirstSeen.Format(timeLayout), r.LastSeen.Format(timeLayout),
			r.TotalFailures, r.PreauthClosed, r.Accepted, userList(r.Usernames))
		if withReasons {
			line += "\t" + strings.Join(r.Reasons, " ")
		}
		fmt.Fprintln(tw, line)
	}
	tw.Flush()
}

type jsonIP struct {
	Rank          int       `json:"rank"`
	IP            string    `json:"ip"`
	Flagged       bool      `json:"flagged"`
	Reasons       []string  `json:"reasons"`
	Score         int       `json:"score"`
	Failures      int       `json:"failures"`
	DistinctUsers int       `json:"distinct_users"`
	Usernames     []string  `json:"usernames"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TotalFailures int       `json:"total_failures"`
	PreauthClosed int       `json:"preauth_closed"`
	Accepted      int       `json:"accepted_logins"`
}

type jsonReport struct {
	Inputs         []string `json:"inputs"`
	Window         string   `json:"window"`
	WindowSeconds  int64    `json:"window_seconds"`
	Threshold      int      `json:"threshold"`
	MinUsers       int      `json:"min_users"`
	ScoreThreshold int      `json:"score_threshold"`
	ScoreFormula   string   `json:"score_formula"`
	Lines          int      `json:"lines"`
	Events         int      `json:"events"`
	Ignored        int      `json:"ignored"`
	Malformed      int      `json:"malformed"`
	FlaggedCount   int      `json:"flagged_count"`
	IPs            []jsonIP `json:"ips"`
}

// WriteJSON writes the machine-readable report. All IPs with failures are
// included, ranked; use the "flagged" field to filter.
func WriteJSON(w io.Writer, s Summary) error {
	out := jsonReport{
		Inputs:         s.Inputs,
		Window:         s.Config.Window.String(),
		WindowSeconds:  int64(s.Config.Window / time.Second),
		Threshold:      s.Config.Threshold,
		MinUsers:       s.Config.MinUsers,
		ScoreThreshold: ScoreThreshold,
		ScoreFormula:   fmt.Sprintf("failures + %d * distinct_users", UserWeight),
		Lines:          s.Stats.Lines,
		Events:         s.Stats.Events,
		Ignored:        s.Stats.Ignored,
		Malformed:      s.Stats.Malformed,
		FlaggedCount:   len(Flagged(s.Reports)),
		IPs:            make([]jsonIP, 0, len(s.Reports)),
	}
	for i, r := range s.Reports {
		reasons := r.Reasons
		if reasons == nil {
			reasons = []string{}
		}
		users := r.Usernames
		if users == nil {
			users = []string{}
		}
		out.IPs = append(out.IPs, jsonIP{
			Rank: i + 1, IP: r.IP.String(), Flagged: r.Flagged, Reasons: reasons,
			Score: r.Score, Failures: r.Failures, DistinctUsers: r.DistinctUsers,
			Usernames: users, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
			TotalFailures: r.TotalFailures, PreauthClosed: r.PreauthClosed, Accepted: r.Accepted,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
