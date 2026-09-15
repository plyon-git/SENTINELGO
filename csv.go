// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const MaxRows = 250000
const MaxUploadBytes int64 = 64 << 20

type Transaction struct {
	OrderID         string    `json:"order_id"`
	Timestamp       string    `json:"timestamp"`
	UserID          string    `json:"user_id"`
	OrderValue      float64   `json:"order_value"`
	IPAddress       string    `json:"ip_address"`
	CardFingerprint string    `json:"card_fingerprint"`
	ItemID          string    `json:"item_id,omitempty"`
	Country         string    `json:"country,omitempty"`
	DeviceInfo      string    `json:"device_info,omitempty"`
	Email           string    `json:"email,omitempty"`
	RiskScore       int       `json:"risk_score"`
	RiskGrade       string    `json:"risk_grade"`
	FlagReason      string    `json:"flag_reason"`
	ClusterID       string    `json:"cluster_id,omitempty"`
	IPRisk          string    `json:"ip_risk"`
	IPRiskType      string    `json:"ip_risk_type"`
	IPIsPrivate     bool      `json:"ip_is_private"`
	Time            time.Time `json:"-"`
}
type MappingReport struct {
	DetectedTemplate string            `json:"detected_template"`
	Mapping          map[string]string `json:"mapping"`
	OriginalColumns  []string          `json:"original_columns"`
	MissingOptional  []string          `json:"missing_optional"`
}
type Dataset struct {
	Rows    []Transaction
	Mapping MappingReport
	SHA256  string
}

var fieldOrder = []string{"timestamp", "user_id", "order_value", "ip_address", "card_fingerprint", "email", "device_info", "country", "order_id", "item_id"}
var aliases = map[string][]string{
	"timestamp":        {"timestamp", "created at", "order date", "created (utc)", "created", "date", "datetime", "time"},
	"user_id":          {"user_id", "customer_id", "customer email", "email", "billing email", "username", "account"},
	"order_value":      {"order_value", "amount", "amount_total", "total", "order total", "total price", "value", "price", "subtotal"},
	"ip_address":       {"ip_address", "browser ip", "client ip", "ip", "remote_addr"},
	"card_fingerprint": {"card_fingerprint", "fingerprint", "payment_token", "payment_method", "source_id", "card", "gateway", "pan"},
	"email":            {"email", "customer_email", "receipt_email", "billing_email", "user_email", "contact"},
	"device_info":      {"device_info", "browser user agent", "user_agent", "client_user_agent", "device", "browser", "os"},
	"country":          {"country", "billing_country", "shipping_country", "customer_country", "nation", "location"},
	"order_id":         {"order_id", "order_name", "name", "payment_intent_id", "charge_id", "transaction_id", "reference", "id"},
	"item_id":          {"item_id", "sku"},
}

func normalized(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, strings.TrimSpace(s))
}
func MapHeaders(headers []string) (MappingReport, map[string]int, error) {
	m := MappingReport{DetectedTemplate: "generic_ecommerce", Mapping: map[string]string{}, OriginalColumns: headers, MissingOptional: []string{}}
	index := map[string]int{}
	cols := map[string]int{}
	for i, h := range headers {
		k := normalized(h)
		if k == "" {
			return m, index, fmt.Errorf("empty column name")
		}
		if _, ok := cols[k]; ok {
			return m, index, fmt.Errorf("duplicate/ambiguous column: %s", h)
		}
		cols[k] = i
	}
	if _, ok := cols["browserip"]; ok {
		m.DetectedTemplate = "shopify_orders"
	} else if _, ok := cols["paymentintentid"]; ok {
		m.DetectedTemplate = "stripe_payments"
	}
	for _, field := range fieldOrder {
		for _, alias := range aliases[field] {
			if i, ok := cols[normalized(alias)]; ok {
				index[field] = i
				m.Mapping[field] = headers[i]
				break
			}
		}
		if _, ok := index[field]; !ok {
			if isRequired(field) {
				return m, index, fmt.Errorf("required column not mapped: %s", field)
			}
			m.MissingOptional = append(m.MissingOptional, field)
		}
	}
	return m, index, nil
}
func isRequired(s string) bool {
	for _, f := range fieldOrder[:5] {
		if s == f {
			return true
		}
	}
	return false
}
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02", "01/02/2006 15:04:05"} {
		if t, e := time.Parse(layout, s); e == nil {
			return t.UTC(), nil
		}
	}
	if len(s) == 10 || len(s) == 13 {
		if n, e := strconv.ParseInt(s, 10, 64); e == nil && n >= 0 {
			if len(s) == 13 {
				return time.UnixMilli(n).UTC(), nil
			}
			return time.Unix(n, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp")
}

// ReadCSV streams decoding and hashes the exact input bytes. Analysis retains
// bounded rows in memory because ordering and cross-entity comparisons need them.
func ReadCSV(ctx context.Context, r io.Reader, maxRows int) (Dataset, error) {
	var d Dataset
	if maxRows < 1 || maxRows > MaxRows {
		return d, fmt.Errorf("row limit must be 1..%d", MaxRows)
	}
	bounded := &io.LimitedReader{R: r, N: MaxUploadBytes + 1}
	h := sha256.New()
	cr := csv.NewReader(io.TeeReader(bounded, h))
	headers, e := cr.Read()
	if e != nil {
		return d, fmt.Errorf("read CSV header: %w", e)
	}
	headers[0] = strings.TrimPrefix(headers[0], "\ufeff")
	report, index, e := MapHeaders(headers)
	if e != nil {
		return d, e
	}
	d.Mapping = report
	for n := 0; ; n++ {
		if e := ctx.Err(); e != nil {
			return d, e
		}
		record, e := cr.Read()
		if bounded.N <= 0 {
			return d, fmt.Errorf("CSV exceeds %d MiB", MaxUploadBytes>>20)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return d, fmt.Errorf("malformed CSV record %d", n+2)
		}
		if n >= maxRows {
			return d, fmt.Errorf("CSV exceeds %d rows", maxRows)
		}
		get := func(k string) string {
			if i, ok := index[k]; ok {
				return strings.TrimSpace(record[i])
			}
			return ""
		}
		for _, f := range fieldOrder[:5] {
			if get(f) == "" {
				return d, fmt.Errorf("record %d: missing %s", n+2, f)
			}
		}
		t, e := ParseTime(get("timestamp"))
		if e != nil {
			return d, fmt.Errorf("record %d: invalid timestamp", n+2)
		}
		v, e := strconv.ParseFloat(get("order_value"), 64)
		if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e12 {
			return d, fmt.Errorf("record %d: amount must be finite and between 0 and 1e12", n+2)
		}
		card := get("card_fingerprint")
		digits := strings.ReplaceAll(strings.ReplaceAll(card, " ", ""), "-", "")
		allDigits := len(digits) >= 13 && len(digits) <= 19
		for _, c := range digits {
			if c < '0' || c > '9' {
				allDigits = false
			}
		}
		if allDigits {
			return d, fmt.Errorf("record %d: possible raw card number; provide a token/fingerprint", n+2)
		}
		id := get("order_id")
		if id == "" {
			id = fmt.Sprintf("ROW-%06d", n+1)
		}
		d.Rows = append(d.Rows, Transaction{OrderID: id, Timestamp: t.Format(time.RFC3339Nano), Time: t, UserID: get("user_id"), OrderValue: v, IPAddress: get("ip_address"), CardFingerprint: card, ItemID: get("item_id"), Country: get("country"), DeviceInfo: get("device_info"), Email: get("email")})
	}
	if len(d.Rows) == 0 {
		return d, fmt.Errorf("CSV contains no transactions")
	}
	d.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
	return d, nil
}
