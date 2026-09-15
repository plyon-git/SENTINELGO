// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Cluster struct {
	ID               string   `json:"cluster_id"`
	Pattern          string   `json:"pattern"`
	Count            int      `json:"transaction_count"`
	RiskLevel        string   `json:"risk_level"`
	SharedAttributes []string `json:"shared_attributes"`
	TotalValue       float64  `json:"total_value"`
}
type Statistics struct {
	TotalRows        int     `json:"total_rows"`
	AvgOrderValue    float64 `json:"avg_order_value"`
	MedianOrderValue float64 `json:"median_order_value"`
	TotalVolume      float64 `json:"total_volume"`
	UniqueUsers      int     `json:"unique_users"`
	UniqueCards      int     `json:"unique_cards"`
	UniqueIPs        int     `json:"unique_ips"`
	DateRangeStart   string  `json:"date_range_start"`
	DateRangeEnd     string  `json:"date_range_end"`
}
type Result struct {
	Identity             BuildIdentity  `json:"identity"`
	TotalRows            int            `json:"total_rows"`
	TotalFlaggedRows     int            `json:"total_flagged_rows"`
	FlaggedRowsTruncated bool           `json:"flagged_rows_truncated"`
	RiskCounts           map[string]int `json:"risk_counts"`
	Clusters             []Cluster      `json:"clusters"`
	FlaggedRows          []Transaction  `json:"flagged_rows"`
	Statistics           Statistics     `json:"statistics"`
	MappingReport        MappingReport  `json:"mapping_report"`
	DatasetSHA256        string         `json:"dataset_sha256"`
	Config               Config         `json:"config"`
	Warnings             []string       `json:"warnings"`
}

var vpnPrefixes = prefixes("104.16.0.0/12", "172.64.0.0/13", "185.222.0.0/16", "198.54.0.0/16", "45.138.0.0/16", "76.76.0.0/16", "146.112.0.0/16", "151.101.0.0/16", "162.158.0.0/15")
var nonPublicPrefixes = prefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100.64.0.0/10")

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}
func IPReputation(s string) (string, string, bool) {
	ip, e := netip.ParseAddr(strings.TrimSpace(s))
	if e != nil {
		return "UNKNOWN", "Invalid IP", true
	}
	ip = ip.Unmap()
	private := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast()
	for _, p := range nonPublicPrefixes {
		private = private || p.Contains(ip)
	}
	if private {
		return "LOW", "Non-public / reserved", true
	}
	for _, p := range vpnPrefixes {
		if p.Contains(ip) {
			return "HIGH", "Static VPN/datacenter heuristic", false
		}
	}
	return "LOW", "No static range match", false
}
func DeviceCategory(s string) string {
	s = strings.ToLower(s)
	switch {
	case s == "":
		return "unknown"
	case strings.Contains(s, "iphone") || strings.Contains(s, "ipad") || strings.Contains(s, "ipod"):
		return "ios"
	case strings.Contains(s, "android"):
		return "android"
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "macintosh") || strings.Contains(s, "mac os"):
		return "mac"
	case strings.Contains(s, "linux"):
		return "linux"
	default:
		return "other"
	}
}

var disposable = map[string]bool{"temp-mail.org": true, "10minutemail.com": true, "guerrillamail.com": true, "mailinator.com": true, "10minute.net": true, "yopmail.com": true, "throwawaymail.com": true, "dispostable.com": true, "trashmail.com": true, "getnada.com": true, "tempmail.com": true, "maildrop.cc": true, "harakirimail.com": true, "sharklasers.com": true, "guerrillamail.org": true, "guerrillamail.net": true}

func DisposableEmail(s string) bool {
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "@")
	return ok && disposable[domain]
}
func unique(rows []Transaction, ids []int, key func(Transaction) string) int {
	seen := map[string]bool{}
	for _, i := range ids {
		seen[key(rows[i])] = true
	}
	return len(seen)
}
func grade(score int, c Config) string {
	for _, g := range []string{"CRITICAL RISK", "INVESTIGATE", "HIGH RISK"} {
		if score >= c.GradeThresholds[g] {
			return g
		}
	}
	return "LOW RISK"
}

// Analyze is a native implementation of the Python backend rule families.
// See docs/PORTING.md for deliberate differences, not a parity claim.
func Analyze(ctx context.Context, d Dataset, c Config, maxResults int) (Result, error) {
	var out Result
	if e := c.Validate(); e != nil {
		return out, e
	}
	if len(d.Rows) == 0 || len(d.Rows) > MaxRows {
		return out, fmt.Errorf("transaction count must be 1..%d", MaxRows)
	}
	if maxResults < 0 || maxResults > MaxRows {
		return out, fmt.Errorf("result limit must be 0..%d", MaxRows)
	}
	c = c.Clone()
	rows := append([]Transaction(nil), d.Rows...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Time.Before(rows[j].Time) })
	n := len(rows)
	cards := map[string][]int{}
	ips := map[string][]int{}
	devices := map[string][]int{}
	previous := map[string]int{}
	users := map[string]bool{}
	cardKeys := []string{}
	ipKeys := []string{}
	flags := make([]map[string]bool, n)
	for i := range rows {
		if i%1024 == 0 {
			if e := ctx.Err(); e != nil {
				return out, e
			}
		}
		r := &rows[i]
		if r.Time.IsZero() || r.UserID == "" || r.IPAddress == "" || r.CardFingerprint == "" || math.IsNaN(r.OrderValue) || math.IsInf(r.OrderValue, 0) || r.OrderValue < 0 || r.OrderValue > 1e12 {
			return out, fmt.Errorf("invalid transaction at sorted index %d", i)
		}
		r.Timestamp = r.Time.UTC().Format(time.RFC3339Nano)
		r.RiskScore = 0
		r.RiskGrade = ""
		r.FlagReason = ""
		r.ClusterID = ""
		r.IPRisk, r.IPRiskType, r.IPIsPrivate = IPReputation(r.IPAddress)
		flags[i] = map[string]bool{}
		if _, ok := cards[r.CardFingerprint]; !ok {
			cardKeys = append(cardKeys, r.CardFingerprint)
		}
		cards[r.CardFingerprint] = append(cards[r.CardFingerprint], i)
		if _, ok := ips[r.IPAddress]; !ok {
			ipKeys = append(ipKeys, r.IPAddress)
		}
		ips[r.IPAddress] = append(ips[r.IPAddress], i)
		if r.DeviceInfo != "" {
			devices[r.DeviceInfo] = append(devices[r.DeviceInfo], i)
		}
		users[r.UserID] = true
		if j, ok := previous[r.UserID]; ok {
			p := rows[j]
			if r.Time.Sub(p.Time) <= time.Duration(c.ATOWindowHours)*time.Hour && r.IPAddress != p.IPAddress && r.DeviceInfo != "" && p.DeviceInfo != "" && DeviceCategory(r.DeviceInfo) != DeviceCategory(p.DeviceInfo) {
				flags[i]["ato_attempt"] = true
				flags[j]["ato_attempt"] = true
			}
		}
		previous[r.UserID] = i
	}
	for _, key := range cardKeys {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		ids := cards[key]
		sum := 0.0
		for p, i := range ids {
			sum += rows[i].OrderValue
			if p >= c.VelocityMinAttempts {
				sum -= rows[ids[p-c.VelocityMinAttempts]].OrderValue
			}
			if p+1 >= c.VelocityMinAttempts {
				start := ids[p+1-c.VelocityMinAttempts]
				if rows[i].Time.Sub(rows[start].Time) <= time.Duration(c.VelocityWindowMinutes)*time.Minute && sum/float64(c.VelocityMinAttempts) < c.VelocityMaxAvgValue {
					flags[i]["card_testing"] = true
				}
			}
		}
	}
	globalRate := float64(n) / math.Max(rows[n-1].Time.Sub(rows[0].Time).Hours(), 0.1)
	for _, key := range ipKeys {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		ids := ips[key]
		if rows[ids[0]].IPIsPrivate {
			continue
		}
		rate := float64(len(ids)) / math.Max(rows[ids[len(ids)-1]].Time.Sub(rows[ids[0]].Time).Hours(), 0.1)
		if len(ids) >= c.BINAttackIPMin && unique(rows, ids, func(t Transaction) string { return t.CardFingerprint }) >= c.BINAttackCardMin && rate > globalRate*c.BINAttackVelocityMultiplier {
			for _, i := range ids {
				flags[i]["bin_attack"] = true
			}
		}
	}
	for _, ids := range devices {
		count := unique(rows, ids, func(t Transaction) string { return t.UserID })
		if count >= c.DeviceMinUsersForFlag && count > c.DeviceManyUsersThreshold {
			for _, i := range ids {
				flags[i]["device_shared"] = true
			}
		}
	}
	out = Result{Identity: Identity(), TotalRows: n, RiskCounts: map[string]int{"CRITICAL RISK": 0, "INVESTIGATE": 0, "HIGH RISK": 0, "LOW RISK": 0}, Clusters: []Cluster{}, FlaggedRows: []Transaction{}, MappingReport: d.Mapping, DatasetSHA256: d.SHA256, Config: c, Warnings: []string{"Heuristic review signals, not proof of fraud or regulatory compliance.", "Static IP/domain lists are inherited heuristics, not live threat intelligence.", "Impossible-travel detection is not implemented; no geolocation is fabricated."}}
	clusterRisk := map[string]string{}
	addCluster := func(ids []int, prefix, pattern, risk string, attrs []string) {
		for _, i := range ids {
			if rows[i].ClusterID != "" {
				return
			}
		}
		id := fmt.Sprintf("%s_%d", prefix, len(out.Clusters)+1)
		value := 0.0
		for _, i := range ids {
			rows[i].ClusterID = id
			value += rows[i].OrderValue
		}
		clusterRisk[id] = risk
		out.Clusters = append(out.Clusters, Cluster{id, pattern, len(ids), risk, attrs, value})
	}
	window := func(ids []int) []int {
		end := rows[ids[0]].Time.Add(time.Duration(c.ClusterTimeWindowHours) * time.Hour)
		p := 0
		for p < len(ids) && !rows[ids[p]].Time.After(end) {
			p++
		}
		return ids[:p]
	}
	for _, key := range ipKeys {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		ids := ips[key]
		if rows[ids[0]].IPIsPrivate {
			continue
		}
		ids = window(ids)
		u := unique(rows, ids, func(t Transaction) string { return t.UserID })
		if len(ids) >= c.IPClusterMinTxns && u >= c.IPClusterMinUsers {
			risk := "INVESTIGATE"
			if len(ids) >= 5 {
				risk = "HIGH"
			}
			addCluster(ids, "IP", "Shared Public IP", risk, []string{"ip=" + key, fmt.Sprintf("%d users", u)})
		}
	}
	for _, key := range cardKeys {
		ids := window(cards[key])
		if len(ids) >= c.CardClusterMinTxns {
			addCluster(ids, "CARD", "Extreme Card Velocity", "CRITICAL", []string{"card=" + key})
		}
	}
	values := make([]float64, n)
	total := 0.0
	for i := range rows {
		if i%1024 == 0 {
			if e := ctx.Err(); e != nil {
				return Result{}, e
			}
		}
		r := &rows[i]
		f := flags[i]
		reasons := []string{}
		add := func(on bool, key, text string) {
			if on {
				r.RiskScore += c.RiskWeights[key]
				reasons = append(reasons, text)
			}
		}
		add(r.OrderValue > 10000, "very_large_amount", "Very Large Amount (>$10k)")
		add(r.OrderValue > 5000 && r.OrderValue <= 10000, "large_amount", "Large Amount (>$5k)")
		add(f["card_testing"], "card_testing", "Card Testing Velocity")
		add(f["ato_attempt"], "ato_attempt", "Possible ATO")
		add(f["bin_attack"], "bin_attack", "BIN Attack Pattern")
		add(DisposableEmail(r.Email), "synthetic_email", "Disposable Email")
		add(r.IPRisk == "HIGH" && !r.IPIsPrivate, "vpn_ip", "VPN/Proxy IP heuristic")
		add(f["device_shared"], "device_shared", "Device Fingerprint Shared")
		if r.ClusterID != "" {
			key := "high_cluster"
			if clusterRisk[r.ClusterID] == "CRITICAL" {
				key = "critical_cluster"
			}
			add(true, key, "Cluster "+r.ClusterID)
		}
		r.RiskGrade = grade(r.RiskScore, c)
		r.FlagReason = strings.Join(reasons, ", ")
		if r.FlagReason == "" {
			r.FlagReason = "Normal"
		}
		out.RiskCounts[r.RiskGrade]++
		if r.RiskGrade != "LOW RISK" {
			out.TotalFlaggedRows++
			if len(out.FlaggedRows) < maxResults {
				out.FlaggedRows = append(out.FlaggedRows, *r)
			}
		}
		values[i] = r.OrderValue
		total += r.OrderValue
	}
	sort.Float64s(values)
	median := values[n/2]
	if n%2 == 0 {
		median = (values[n/2-1] + values[n/2]) / 2
	}
	out.Statistics = Statistics{n, total / float64(n), median, total, len(users), len(cards), len(ips), rows[0].Timestamp, rows[n-1].Timestamp}
	out.FlaggedRowsTruncated = out.TotalFlaggedRows > len(out.FlaggedRows)
	return out, nil
}
