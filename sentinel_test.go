// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const csvHeader = "timestamp,user_id,order_value,ip_address,card_fingerprint,device_info,email\n"
const validCSV = csvHeader + "2026-01-01T00:00:00Z,alice,100,192.168.1.1,token-1,iPhone,alice@example.com\n"

func row(i int, card, user, ip string, value float64) Transaction {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
	return Transaction{OrderID: fmt.Sprint(i), Time: ts, Timestamp: ts.Format(time.RFC3339), UserID: user, OrderValue: value, IPAddress: ip, CardFingerprint: card, DeviceInfo: "iPhone", Email: "user@example.com"}
}
func analyze(t *testing.T, rows []Transaction) Result {
	t.Helper()
	r, e := Analyze(context.Background(), Dataset{Rows: rows}, DefaultConfig(), MaxRows)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestCSVHashAndMapping(t *testing.T) {
	d, e := ReadCSV(context.Background(), strings.NewReader(validCSV), 10)
	if e != nil {
		t.Fatal(e)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(validCSV)))
	if d.SHA256 != want || len(d.Rows) != 1 || d.Rows[0].OrderValue != 100 || d.Mapping.Mapping["user_id"] != "user_id" {
		t.Fatalf("unexpected dataset: %+v", d)
	}
}
func TestCSVQuotedNewlineAndBOM(t *testing.T) {
	s := "\ufeff" + csvHeader + "2026-01-01 00:00:00,\"alice,\ncompany\",100,192.168.1.1,token-1,iPhone,a@example.com\n"
	d, e := ReadCSV(context.Background(), strings.NewReader(s), 10)
	if e != nil || len(d.Rows) != 1 || d.Rows[0].UserID != "alice,\ncompany" {
		t.Fatalf("%+v %v", d, e)
	}
}
func TestCSVRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"empty": "", "no_rows": csvHeader, "missing": "foo,bar\na,b\n", "duplicate": "timestamp,timestamp\na,b\n", "nan": strings.Replace(validCSV, ",100,", ",NaN,", 1), "infinity": strings.Replace(validCSV, ",100,", ",Inf,", 1), "negative": strings.Replace(validCSV, ",100,", ",-1,", 1), "bad_time": strings.Replace(validCSV, "2026-01-01T00:00:00Z", "nonsense", 1), "blank_user": strings.Replace(validCSV, ",alice,", ",,", 1), "ragged": validCSV + "a,b\n", "raw_card": strings.Replace(validCSV, "token-1", "4111111111111111", 1)}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := ReadCSV(context.Background(), strings.NewReader(s), 10); e == nil {
				t.Fatal("accepted invalid CSV")
			}
		})
	}
}
func TestCSVRowLimit(t *testing.T) {
	if _, e := ReadCSV(context.Background(), strings.NewReader(validCSV+strings.SplitN(validCSV, "\n", 2)[1]), 1); e == nil {
		t.Fatal("row cap not enforced")
	}
}
func TestSourceAliases(t *testing.T) {
	h := []string{"Created at", "Customer Email", "Total", "Browser Ip", "Payment Method"}
	m, _, e := MapHeaders(h)
	if e != nil || m.DetectedTemplate != "shopify_orders" || m.Mapping["order_value"] != "Total" {
		t.Fatalf("%+v %v", m, e)
	}
}
func TestSourceGradeOrder(t *testing.T) {
	c := DefaultConfig()
	for n, want := range map[int]string{0: "LOW RISK", 1: "LOW RISK", 2: "HIGH RISK", 3: "HIGH RISK", 4: "INVESTIGATE", 5: "INVESTIGATE", 6: "CRITICAL RISK"} {
		if got := grade(n, c); got != want {
			t.Fatalf("%d: %s", n, got)
		}
	}
}
func TestCardTestingWindow(t *testing.T) {
	rows := []Transaction{}
	for i := 0; i < 5; i++ {
		rows = append(rows, row(i, "shared", "same", "192.168.1.1", 5))
	}
	r := analyze(t, rows)
	if r.TotalFlaggedRows != 1 || r.FlaggedRows[0].RiskScore != 4 {
		t.Fatalf("%+v", r)
	}
	rows[4].Time = rows[4].Time.Add(time.Hour)
	if r := analyze(t, rows); r.TotalFlaggedRows != 0 {
		t.Fatal("old attempts crossed time window")
	}
}
func TestAccountTakeoverUsesPerUserHistory(t *testing.T) {
	a, b, c := row(0, "a", "alice", "192.168.1.1", 100), row(1, "b", "bob", "192.168.1.2", 100), row(2, "c", "alice", "192.168.1.3", 100)
	c.DeviceInfo = "Windows NT 10.0"
	r := analyze(t, []Transaction{c, b, a})
	if r.TotalFlaggedRows != 2 {
		t.Fatalf("%+v", r)
	}
	for _, v := range r.FlaggedRows {
		if v.UserID != "alice" || v.RiskScore != 3 {
			t.Fatalf("wrong previous user: %+v", v)
		}
	}
}
func TestMissingDeviceDoesNotInventATO(t *testing.T) {
	a, b := row(0, "a", "alice", "192.168.1.1", 100), row(1, "b", "alice", "192.168.1.2", 100)
	a.DeviceInfo = ""
	r := analyze(t, []Transaction{a, b})
	if r.TotalFlaggedRows != 0 {
		t.Fatal("unknown device treated as evidence")
	}
}
func TestBINAttack(t *testing.T) {
	rows := []Transaction{}
	for i := 0; i < 10; i++ {
		rows = append(rows, row(i, fmt.Sprint(i), "same", "8.8.4.4", 100))
	}
	rows = append(rows, row(1440, "baseline", "other", "192.168.1.2", 100))
	r := analyze(t, rows)
	if r.TotalFlaggedRows != 10 {
		t.Fatalf("%+v", r)
	}
	for _, v := range r.FlaggedRows {
		if !strings.Contains(v.FlagReason, "BIN Attack") {
			t.Fatalf("%+v", v)
		}
	}
}
func TestDeviceSharing(t *testing.T) {
	rows := []Transaction{}
	for i := 0; i < 21; i++ {
		rows = append(rows, row(i, fmt.Sprint(i), fmt.Sprint(i), fmt.Sprintf("192.168.1.%d", i+1), 6000))
	}
	r := analyze(t, rows)
	if r.TotalFlaggedRows != 21 {
		t.Fatalf("%+v", r)
	}
}
func TestIPClusterAndDeterminism(t *testing.T) {
	rows := []Transaction{}
	for i := 0; i < 5; i++ {
		rows = append(rows, row(i, fmt.Sprint(i), fmt.Sprint(i%2), "8.8.4.4", 100))
	}
	a, b := analyze(t, rows), analyze(t, rows)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if !bytes.Equal(x, y) || len(a.Clusters) != 1 || a.Clusters[0].RiskLevel != "HIGH" {
		t.Fatalf("%+v", a)
	}
}
func TestCardClusterNoNullScores(t *testing.T) {
	rows := []Transaction{}
	for i := 0; i < 8; i++ {
		rows = append(rows, row(i, "shared", "alice", "192.168.1.1", 5))
	}
	r := analyze(t, rows)
	if len(r.Clusters) != 1 || r.TotalFlaggedRows != 8 || r.RiskCounts["CRITICAL RISK"] != 4 {
		t.Fatalf("%+v", r)
	}
}
func TestUnclusteredScoresAndResultCap(t *testing.T) {
	rows := []Transaction{row(0, "a", "a", "192.168.1.1", 12000), row(1, "b", "b", "192.168.1.2", 14000)}
	r, e := Analyze(context.Background(), Dataset{Rows: rows}, DefaultConfig(), 1)
	if e != nil || r.TotalFlaggedRows != 2 || len(r.FlaggedRows) != 1 || !r.FlaggedRowsTruncated || r.Statistics.MedianOrderValue != 13000 {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestIPHeuristic(t *testing.T) {
	for _, s := range []string{"192.168.1.1", "::1", "203.0.113.5", "garbage"} {
		_, _, private := IPReputation(s)
		if !private {
			t.Fatal(s)
		}
	}
	risk, _, private := IPReputation("104.16.1.1")
	if risk != "HIGH" || private {
		t.Fatal("source CIDR heuristic missing")
	}
}
func TestConfigValidationAndClone(t *testing.T) {
	c := DefaultConfig()
	d := c.Clone()
	d.RiskWeights["card_testing"] = 9
	if c.RiskWeights["card_testing"] != 4 {
		t.Fatal("clone aliases map")
	}
	c.VelocityMinAttempts = 0
	if c.Validate() == nil {
		t.Fatal("bad threshold allowed")
	}
	if ModeConfig(DefaultConfig(), true).Validate() != nil {
		t.Fatal("invalid demo config")
	}
}
func TestCanceledWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ReadCSV(ctx, strings.NewReader(validCSV), 10); e == nil {
		t.Fatal("CSV ignored cancellation")
	}
	if _, e := Analyze(ctx, Dataset{Rows: []Transaction{row(0, "a", "a", "192.168.1.1", 10)}}, DefaultConfig(), 10); e == nil {
		t.Fatal("engine ignored cancellation")
	}
}
func TestGeneratorDeterminismAndSchema(t *testing.T) {
	o := GenerateOptions{Rows: 1000, Seed: 42, End: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)}
	var a, b bytes.Buffer
	sa, e := Generate(context.Background(), &a, o)
	if e != nil {
		t.Fatal(e)
	}
	sb, e := Generate(context.Background(), &b, o)
	if e != nil || !bytes.Equal(a.Bytes(), b.Bytes()) || sa.LabeledFraudRows != sb.LabeledFraudRows {
		t.Fatal("generator not reproducible")
	}
	records, e := csv.NewReader(bytes.NewReader(a.Bytes())).ReadAll()
	if e != nil || len(records) != 1001 || len(records[0]) != 10 {
		t.Fatal("wrong schema/count")
	}
	d, e := ReadCSV(context.Background(), bytes.NewReader(a.Bytes()), MaxRows)
	if e != nil || len(d.Rows) != 1000 {
		t.Fatalf("roundtrip: %v", e)
	}
}
func TestGeneratorLabelsNeverScore(t *testing.T) {
	a := validCSV
	b := strings.Replace(a, "device_info,email\n", "device_info,email,is_fraud\n", 1)
	b = strings.TrimSuffix(b, "\n") + ",true\n"
	da, e := ReadCSV(context.Background(), strings.NewReader(a), 10)
	if e != nil {
		t.Fatal(e)
	}
	db, e := ReadCSV(context.Background(), strings.NewReader(b), 10)
	if e != nil {
		t.Fatal(e)
	}
	ra, rb := analyze(t, da.Rows), analyze(t, db.Rows)
	if ra.TotalFlaggedRows != rb.TotalFlaggedRows {
		t.Fatal("label leakage")
	}
}
func TestGeneratorInvalidArguments(t *testing.T) {
	if _, e := Generate(context.Background(), io.Discard, GenerateOptions{Rows: 0, End: time.Now()}); e == nil {
		t.Fatal("zero rows allowed")
	}
}
func newTestHandler(t *testing.T, o ServerOptions) http.Handler {
	t.Helper()
	h, e := NewHandler(o)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func request(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func multipartRequest(h http.Handler, path, data string) *httptest.ResponseRecorder {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	part, _ := mw.CreateFormFile("file", "orders.csv")
	_, _ = io.WriteString(part, data)
	_ = mw.Close()
	r := httptest.NewRequest("POST", "http://localhost"+path, &b)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHTTPUploadAndPreview(t *testing.T) {
	h := newTestHandler(t, ServerOptions{MaxResults: 10})
	for _, p := range []string{"/upload", "/mapping/preview"} {
		w := multipartRequest(h, p, validCSV)
		if w.Code != 200 || !strings.Contains(w.Body.String(), Watermark) {
			t.Fatalf("%s %d %s", p, w.Code, w.Body.String())
		}
	}
}
func TestHTTPBadCSVAndMethods(t *testing.T) {
	h := newTestHandler(t, ServerOptions{MaxResults: 10})
	if w := multipartRequest(h, "/upload", "bad,data\na,b\n"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/upload", "", nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/config", "{}", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestHTTPAuthenticationAndOrigins(t *testing.T) {
	key := strings.Repeat("a", 32)
	h := newTestHandler(t, ServerOptions{APIKey: key, MaxResults: 10})
	if w := request(h, "GET", "/config", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/config", "", map[string]string{"Authorization": "Bearer " + key}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/health", "", map[string]string{"Origin": "https://evil.example"}); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/health", "", nil); w.Header().Get("X-Sentinel-Owner") != Owner || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing security metadata")
	}
}
func TestHTTPHostGuard(t *testing.T) {
	h := newTestHandler(t, ServerOptions{MaxResults: 10})
	r := httptest.NewRequest("GET", "http://attacker.example/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("rebound Host allowed")
	}
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "localhost.attacker:8080"} {
		if LocalAddress(addr) {
			t.Fatal(addr)
		}
	}
}
func TestHTTPAdminValidation(t *testing.T) {
	admin := strings.Repeat("b", 32)
	h := newTestHandler(t, ServerOptions{AdminKey: admin, MaxResults: 10})
	headers := map[string]string{"X-Sentinel-Admin-Token": admin}
	for _, body := range []string{"null", "[]", "{\"unknown\":1}", "{\"velocity_min_attempts\":0}", "{} {}"} {
		if w := request(h, "POST", "/config", body, headers); w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	if w := request(h, "POST", "/config", "{\"velocity_min_attempts\":7}", headers); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "POST", "/set_mode", "{\"demo_mode\":\"false\"}", headers); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/set_mode", "{\"demo_mode\":true}", headers); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestHTTPConcurrency(t *testing.T) {
	admin := strings.Repeat("b", 32)
	h := newTestHandler(t, ServerOptions{AdminKey: admin, MaxResults: 10})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request(h, "POST", "/set_mode", "{\"demo_mode\":true}", map[string]string{"X-Sentinel-Admin-Token": admin})
			request(h, "GET", "/config", "", nil)
			multipartRequest(h, "/upload", validCSV)
		}()
	}
	wg.Wait()
}
func TestHTTPStaticAssets(t *testing.T) {
	h := newTestHandler(t, ServerOptions{MaxResults: 10})
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		if w := request(h, "GET", p, "", nil); w.Code != 200 {
			t.Fatalf("%s %d", p, w.Code)
		}
	}
	if w := request(h, "GET", "/WATERMARK.json", "", nil); w.Code != 404 {
		t.Fatal("source files exposed")
	}
}
func TestShortTokensRejected(t *testing.T) {
	if _, e := NewHandler(ServerOptions{APIKey: "short"}); e == nil {
		t.Fatal("short token accepted")
	}
}
func TestManifestTamperingAndMissingFiles(t *testing.T) {
	if e := Verify("."); e != nil {
		t.Fatal(e)
	}
	var m Manifest
	if e := json.Unmarshal(baseline, &m); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	for name := range m.Files {
		b, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(root, filepath.FromSlash(name))
		if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	p := filepath.Join(root, "WATERMARK.json")
	_ = os.WriteFile(p, baseline, 0644)
	if e := Verify(root); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "go.mod")
	original, _ := os.ReadFile(target)
	_ = os.WriteFile(target, []byte("tampered"), 0644)
	if Verify(root) == nil {
		t.Fatal("tampering accepted")
	}
	_ = os.Remove(target)
	if Verify(root) == nil {
		t.Fatal("missing file accepted")
	}
	_ = os.WriteFile(target, original, 0644)
	_ = os.WriteFile(p, bytes.Replace(baseline, []byte(Owner), []byte("Other Owner"), 1), 0644)
	if Verify(root) == nil {
		t.Fatal("owner alteration accepted")
	}
}
