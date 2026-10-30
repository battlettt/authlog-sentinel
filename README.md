# AuthLog Sentinel

AuthLog Sentinel is a small command-line tool that reads Linux SSH auth logs
(`/var/log/auth.log`, `/var/log/secure`, or `journalctl` output in syslog
format) and reports which source IPs look like SSH brute-force or
credential-stuffing attackers. It ranks them with a simple score that you can
check by hand.

> **It is read-only.** AuthLog Sentinel never blocks anything, never runs
> `iptables`/`nft`, never touches the firewall, and never modifies the system.
> `--blocklist` only *prints* suggested rules, and every rule is commented
> out. Applying them is a human decision.

Written in Go with the standard library only. No dependencies, no network calls.

## Why it matters

Brute-force and credential-stuffing attacks against internet-facing SSH are
among the most common initial-access vectors. Any host with port 22 open gets
a constant stream of password guesses. Two patterns matter most:

- **Brute force:** many password attempts against one account (usually `root`)
  from one IP, sometimes slowed down to stay under rate limits.
- **Credential stuffing / username spraying:** one IP trying many *different*
  usernames (`admin`, `oracle`, `ubuntu`, `pi`, ...) with leaked or default
  credentials.

Raw logs bury these patterns in thousands of lines. AuthLog Sentinel groups
them per IP so you can see what happened and decide what to do.

## Build

Requires Go 1.24+.

```sh
go build ./...                          # compile check
go build -o authlog-sentinel .          # produce the binary
go vet ./... && go test ./...           # vet and run the tests
```

## Usage

```
authlog-sentinel [flags] FILE [FILE...]
authlog-sentinel [flags] -              # read from stdin

  --window 60m      sliding time window (Go duration: 30m, 2h, 90m, ...)
  --threshold 10    flag an IP with at least this many failures in one window
  --min-users 5     flag an IP that tried at least this many distinct usernames in one window
  --format text     text (default) or json
  --blocklist       print flagged IPs plus commented iptables/nftables suggestions
```

Flags go before file names. Exit codes: `0` success, `1` I/O error, `2` usage error.

### Example 1: ranked text report

```sh
./authlog-sentinel examples/sample-auth.log
```

```
AuthLog Sentinel report
Inputs:     examples/sample-auth.log
Lines:      150 read, 137 sshd auth events, 9 ignored, 4 malformed (skipped)
Window:     1h0m0s sliding
Flag rule:  failures >= 10 OR distinct users >= 5 OR score >= 25
Score:      failures + 3 x distinct usernames (worst window per IP)

FLAGGED IPs (3), worst first
RANK  IP                     SCORE  FAILS  USERS  FIRST SEEN           LAST SEEN            TOTAL  PREAUTH  ACCEPTED  USERNAMES                                      REASONS
1     203.0.113.77           48     12     12     2026-10-28 03:10:02  2026-10-28 03:22:21  12     12       0         admin,ftpuser,git,guest,hadoop,oracle,+6 more  failures>=10 users>=5 score>=25
2     198.51.100.23          28     25     1      2026-10-28 02:00:00  2026-10-28 02:16:04  25     0        1         root                                           failures>=10 score>=25
3     2001:db8:dead:beef::7  14     11     1      2026-10-28 05:30:00  2026-10-28 05:34:43  11     0        0         alice                                          failures>=10

Below threshold (4)
RANK  IP              SCORE  FAILS  USERS  FIRST SEEN           LAST SEEN            TOTAL  PREAUTH  ACCEPTED  USERNAMES
1     198.51.100.200  12     9      1      2026-10-28 00:03:00  2026-10-28 00:59:00  44     0        0         root
2     203.0.113.5     9      3      2      2026-10-28 06:15:00  2026-10-28 06:18:00  3      3        0         git,jenkins
3     203.0.113.9     8      2      2      2026-10-28 08:00:00  2026-10-28 08:05:00  2      2        0         (empty),support
4     192.0.2.11      4      1      1      2026-10-28 07:11:40  2026-10-28 07:11:40  1      0        1         alice

WARNING: flagged IP 198.51.100.23 also has 1 accepted login(s); investigate for possible compromise.
```

`198.51.100.200` is a *slow* brute force: one guess every 7 minutes, so it
never reaches 10 failures in any 60-minute window (TOTAL shows 44 over the whole
log). A wider window catches it:

```sh
./authlog-sentinel --window 2h examples/sample-auth.log
```

```
FLAGGED IPs (4), worst first
RANK  IP                     SCORE  FAILS  USERS  ...  REASONS
1     203.0.113.77           48     12     12     ...  failures>=10 users>=5 score>=25
2     198.51.100.23          28     25     1      ...  failures>=10 score>=25
3     198.51.100.200         21     18     1      ...  failures>=10
4     2001:db8:dead:beef::7  14     11     1      ...  failures>=10
```

### Example 2: JSON for scripts and SIEM ingestion

```sh
sudo cat /var/log/auth.log | ./authlog-sentinel --format json - | jq '.ips[] | select(.flagged) | .ip'
./authlog-sentinel --format json --window 2h examples/sample-auth.log
```

```json
{
  "inputs": ["examples/sample-auth.log"],
  "window": "2h0m0s",
  "window_seconds": 7200,
  "threshold": 10,
  "min_users": 5,
  "score_threshold": 25,
  "score_formula": "failures + 3 * distinct_users",
  "lines": 150, "events": 137, "ignored": 9, "malformed": 4,
  "flagged_count": 4,
  "ips": [
    {
      "rank": 1,
      "ip": "203.0.113.77",
      "flagged": true,
      "reasons": ["failures>=10", "users>=5", "score>=25"],
      "score": 48,
      "failures": 12,
      "distinct_users": 12,
      "usernames": ["admin", "ftpuser", "git", "guest", "hadoop", "oracle", "pi", "postgres", "support", "test", "ubuntu", "user"],
      "first_seen": "2026-10-28T03:10:02Z",
      "last_seen": "2026-10-28T03:22:21Z",
      "total_failures": 12,
      "preauth_closed": 12,
      "accepted_logins": 0
    }
  ]
}
```

(Abbreviated; the real output is indented and lists every IP with at least one failure. Filter on `flagged`.)

### Example 3: blocklist suggestions

```sh
./authlog-sentinel --blocklist /var/log/auth.log /var/log/auth.log.1 > review-me.txt
./authlog-sentinel --blocklist examples/sample-auth.log
```

```
# AuthLog Sentinel blocklist (SUGGESTIONS ONLY)
# Nothing has been blocked. This tool never modifies the firewall or the system.
# Review every address before applying: check for shared NAT/VPN egress, your own
# monitoring or bastion hosts, and users who simply mistyped a password.
# Window 1h0m0s; flag rule: failures >= 10 OR distinct users >= 5 OR score >= 25
# Flagged IPs: 3
203.0.113.77
198.51.100.23
2001:db8:dead:beef::7

# --- Example iptables rules (commented out; review, then uncomment to use) ---
# iptables -I INPUT -s 203.0.113.77 -p tcp --dport 22 -j DROP
# iptables -I INPUT -s 198.51.100.23 -p tcp --dport 22 -j DROP
# ip6tables -I INPUT -s 2001:db8:dead:beef::7 -p tcp --dport 22 -j DROP

# --- Example nftables rules (commented out; assumes an existing 'inet filter' table with an 'input' chain) ---
# nft add rule inet filter input ip saddr { 203.0.113.77, 198.51.100.23 } tcp dport 22 drop
# nft add rule inet filter input ip6 saddr { 2001:db8:dead:beef::7 } tcp dport 22 drop
```

## Using the blocklist output safely

The blocklist is a starting point for a human decision, not something to pipe
into a shell.

1. **Review every IP.** Make sure none is your own office, VPN or NAT egress,
   CI runner, monitoring system, or jump host. A colleague with a stale saved
   password can trip `--threshold`.
2. **Check the ACCEPTED column first.** A flagged IP with accepted logins may
   have gotten in. That is an incident to investigate, not just an IP to block.
3. **Pick one firewall.** Use either the iptables or the nftables lines, whichever
   your host actually uses. Don't use both. The nftables lines assume an
   existing `inet filter` table with an `input` chain; adjust them to your ruleset.
4. **Apply by hand, test, and make it persistent deliberately.** Keep a second
   session open so you don't lock yourself out. Remember that rules added this
   way don't survive a reboot unless you save them.
5. **Prefer durable fixes.** Blocking IPs only treats the symptom. Disabling
   password authentication (`PasswordAuthentication no`), disabling root
   login, and using key-based or MFA logins remove the attack surface.

The uncommented lines are bare IP addresses, one per line, so
`grep -v '^#' review-me.txt` gives you a plain list to feed into an ipset or
an allow/deny review process.

## How detection works

**Recognized sshd lines** (program `sshd` or `sshd-session`):

| Line shape | Treated as |
|---|---|
| `Failed password for [invalid user] USER from IP port N ssh2` | failure |
| `Failed publickey for [invalid user] USER from IP port N ssh2[: KEY]` | failure |
| `Invalid user USER from IP port N` | failure, unless a `Failed` line exists for the same IP and source port within 10 minutes (sshd usually logs both for one attempt; it is counted once) |
| `Connection closed by IP port N [preauth]` | context (PREAUTH column) |
| `Accepted password\|publickey for USER from IP port N ssh2` | context (ACCEPTED column) |

Timestamps can be traditional syslog (`Oct 28 03:12:45`) or RFC 3339
(`2026-10-28T03:12:45.123456+00:00`). Traditional timestamps have no year, so
the current year is assumed. A date more than two days in the future is moved
to the previous year, which handles December logs read in January.

**Skipped lines** never stop the run. Blank lines and `#` comments are
ignored silently. Other syslog lines that are not one of the shapes above
(cron, PAM, other sshd messages) are counted as *ignored*. Lines without a
valid syslog header, or with an invalid IP or port, are counted as *malformed*.

**Windowing.** Failures are grouped per source IP and sorted by time. A
window of length `--window` slides over them; events whose time span is at
most the window length aggregate together, and older events drop out. For each
IP the report shows its worst window. That is the highest-scoring window that
trips a flag rule, or the highest-scoring window overall if none does. FAILS,
USERS, SCORE, FIRST SEEN, LAST SEEN and USERNAMES describe that window. TOTAL,
PREAUTH and ACCEPTED cover the whole input.

**Score** = `failures + 3 x distinct usernames`. The username weight puts
credential stuffing near the top: 12 attempts across 12 usernames scores 48,
while 25 attempts against `root` scores 28.

**Flag rule:** an IP is flagged when, within one window,
`failures >= --threshold` (default 10) **or** `distinct usernames >= --min-users`
(default 5) **or** `score >= 25`. The REASONS column says which rules tripped.

Usernames come from the attacker, so the text report escapes non-printable
characters and quotes names that contain spaces or commas.

## What it deliberately does NOT do

- **No auto-blocking.** It never runs iptables, nftables, fail2ban, ipset,
  or anything else, and it never writes to any system file. It only reads the
  files you name and writes to stdout/stderr.
- **No live tailing.** It analyzes the log content it is given and exits. It
  does not follow files or watch the journal.
- **No agent or daemon.** Nothing runs in the background, and there is no
  service, network listener, or phoning home. It makes no network calls at all.
- No GeoIP, reputation lookups, or reverse DNS. Hostnames in `from` fields
  (sshd with `UseDNS yes`) are counted as malformed, not resolved.

## Sample data

`examples/sample-auth.log` is **synthetic**: every line was generated for this
project and uses documentation IP ranges (RFC 5737, RFC 3849). It contains
every supported line shape, plus credential stuffing (`203.0.113.77`), fast
and slow root brute force (`198.51.100.23`, `198.51.100.200`), an IPv6 attacker,
publickey probing, invalid-user probes with an empty username, a preauth-only
scanner, legitimate logins, unrelated noise, and malformed lines.

## Project layout

```
main.go        CLI flags, input handling, output selection
parser.go      syslog + sshd line parsing
analyzer.go    per-IP sliding window, scoring, flagging
report.go      text and JSON reports
blocklist.go   commented iptables/nftables suggestions
*_test.go      unit and CLI tests
examples/sample-auth.log   synthetic test log
```
