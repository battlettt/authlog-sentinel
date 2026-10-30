package main

import (
	"fmt"
	"io"
	"strings"
)

// WriteBlocklist prints the flagged IPs, one per line, followed by example
// iptables and nftables rules. Every rule is a COMMENT: this tool never runs
// them and never touches the firewall. A human must review and apply them.
func WriteBlocklist(w io.Writer, s Summary) error {
	flagged := Flagged(s.Reports)
	var b strings.Builder
	b.WriteString("# AuthLog Sentinel blocklist (SUGGESTIONS ONLY)\n")
	b.WriteString("# Nothing has been blocked. This tool never modifies the firewall or the system.\n")
	b.WriteString("# Review every address before applying: check for shared NAT/VPN egress, your own\n")
	b.WriteString("# monitoring or bastion hosts, and users who simply mistyped a password.\n")
	fmt.Fprintf(&b, "# Window %s; flag rule: failures >= %d OR distinct users >= %d OR score >= %d\n",
		s.Config.Window, s.Config.Threshold, s.Config.MinUsers, ScoreThreshold)
	fmt.Fprintf(&b, "# Flagged IPs: %d\n", len(flagged))

	if len(flagged) == 0 {
		b.WriteString("# No IPs flagged; no rules suggested.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	for _, r := range flagged {
		fmt.Fprintf(&b, "%s\n", r.IP)
	}

	var v4, v6 []string
	for _, r := range flagged {
		if r.IP.Is4() {
			v4 = append(v4, r.IP.String())
		} else {
			v6 = append(v6, r.IP.String())
		}
	}

	b.WriteString("\n# --- Example iptables rules (commented out; review, then uncomment to use) ---\n")
	for _, ip := range v4 {
		fmt.Fprintf(&b, "# iptables -I INPUT -s %s -p tcp --dport 22 -j DROP\n", ip)
	}
	for _, ip := range v6 {
		fmt.Fprintf(&b, "# ip6tables -I INPUT -s %s -p tcp --dport 22 -j DROP\n", ip)
	}

	b.WriteString("\n# --- Example nftables rules (commented out; assumes an existing 'inet filter' table with an 'input' chain) ---\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "# nft add rule inet filter input ip saddr { %s } tcp dport 22 drop\n", strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "# nft add rule inet filter input ip6 saddr { %s } tcp dport 22 drop\n", strings.Join(v6, ", "))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
