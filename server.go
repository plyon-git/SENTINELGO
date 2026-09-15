// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
)

type ServerOptions struct {
	APIKey, AdminKey string
	MaxResults       int
}
type api struct {
	mu      sync.RWMutex
	config  Config
	options ServerOptions
	slots   chan struct{}
}

func NewHandler(o ServerOptions) (http.Handler, error) {
	if o.APIKey != "" && len(o.APIKey) < 32 {
		return nil, fmt.Errorf("SENTINEL_API_TOKEN must contain at least 32 bytes")
	}
	if o.AdminKey != "" && len(o.AdminKey) < 32 {
		return nil, fmt.Errorf("SENTINEL_ADMIN_TOKEN must contain at least 32 bytes")
	}
	if o.AdminKey != "" && o.AdminKey == o.APIKey {
		return nil, fmt.Errorf("admin and API tokens must differ")
	}
	if o.MaxResults < 0 || o.MaxResults > MaxRows {
		return nil, fmt.Errorf("invalid max-results")
	}
	a := &api{config: DefaultConfig(), options: o, slots: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"status": "healthy", "engine": "Go", "identity": Identity()})
	})
	mux.HandleFunc("GET /build", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, Identity()) })
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		c := a.config.Clone()
		a.mu.RUnlock()
		respond(w, 200, c)
	})
	mux.HandleFunc("POST /config", a.updateConfig)
	mux.HandleFunc("POST /set_mode", a.updateMode)
	mux.HandleFunc("POST /upload", a.upload)
	mux.HandleFunc("POST /mapping/preview", a.upload)
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		p := p
		pattern := p
		if pattern == "/" {
			pattern = "/{$}"
		}
		mux.HandleFunc("GET "+pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != p {
				http.NotFound(w, r)
				return
			}
			name := strings.TrimPrefix(p, "/")
			if name == "" {
				name = "index.html"
			}
			b, e := assets.ReadFile("web/" + name)
			if e != nil {
				http.NotFound(w, r)
				return
			}
			mime := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
			w.Header().Set("Content-Type", mime[name])
			_, _ = w.Write(b)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Sentinel-Owner", Owner)
		w.Header().Set("X-Sentinel-Watermark", Watermark)
		if o.APIKey == "" && !LocalAddress(r.Host) {
			failure(w, 403, "non-local Host requires authentication")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != r.Host {
				failure(w, 403, "cross-origin requests are not allowed")
				return
			}
		}
		public := r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css" || r.URL.Path == "/health"
		if !public && o.APIKey != "" && !validToken(r.Header.Get("Authorization"), o.APIKey) {
			failure(w, 401, "valid bearer API token required")
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

// LocalAddress is intentionally strict: hostnames other than localhost do not
// become trusted merely because they resolve to loopback (DNS rebinding).
func LocalAddress(address string) bool {
	host := address
	if h, _, e := net.SplitHostPort(address); e == nil {
		host = h
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}
func validToken(got, expected string) bool {
	if !strings.HasPrefix(got, "Bearer ") {
		return false
	}
	a := sha256.Sum256([]byte(strings.TrimPrefix(got, "Bearer ")))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func failure(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e := dec.Decode(dst); e != nil {
		return e
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		return fmt.Errorf("exactly one JSON object is required")
	}
	return nil
}
func (a *api) adminBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if a.options.AdminKey == "" {
		failure(w, 403, "configuration writes are disabled; set SENTINEL_ADMIN_TOKEN")
		return nil, false
	}
	if !validToken("Bearer "+r.Header.Get("X-Sentinel-Admin-Token"), a.options.AdminKey) {
		failure(w, 403, "valid admin token required")
		return nil, false
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		failure(w, 413, "configuration body exceeds limit")
		return nil, false
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		failure(w, 400, "JSON object required")
		return nil, false
	}
	return b, true
}
func (a *api) updateConfig(w http.ResponseWriter, r *http.Request) {
	b, ok := a.adminBody(w, r)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.config.Clone()
	if e := decode(b, &c); e != nil {
		failure(w, 400, "unknown setting or invalid JSON type")
		return
	}
	if e := c.Validate(); e != nil {
		failure(w, 400, e.Error())
		return
	}
	a.config = c
	respond(w, 200, map[string]any{"status": "updated", "config": c})
}
func (a *api) updateMode(w http.ResponseWriter, r *http.Request) {
	b, ok := a.adminBody(w, r)
	if !ok {
		return
	}
	var payload struct {
		Demo *bool `json:"demo_mode"`
	}
	if e := decode(b, &payload); e != nil || payload.Demo == nil {
		failure(w, 400, "demo_mode must be a boolean")
		return
	}
	a.mu.Lock()
	a.config = ModeConfig(a.config, *payload.Demo)
	a.mu.Unlock()
	respond(w, 200, map[string]bool{"demo_mode": *payload.Demo})
}
func (a *api) upload(w http.ResponseWriter, r *http.Request) {
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		failure(w, 429, "another analysis is running; retry after it completes")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes+(1<<20))
	if e := r.ParseMultipartForm(1 << 20); e != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(e, &sizeErr) {
			failure(w, 413, "upload exceeds 64 MiB plus multipart allowance")
		} else {
			failure(w, 400, "invalid multipart upload")
		}
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, e := r.FormFile("file")
	if e != nil {
		failure(w, 400, "multipart file field is required")
		return
	}
	defer file.Close()
	if strings.ToLower(filepath.Ext(header.Filename)) != ".csv" {
		failure(w, 400, "file must have .csv extension")
		return
	}
	if header.Size > MaxUploadBytes {
		failure(w, 413, "CSV exceeds 64 MiB")
		return
	}
	d, e := ReadCSV(r.Context(), file, MaxRows)
	if e != nil {
		failure(w, 400, e.Error())
		return
	}
	if r.URL.Path == "/mapping/preview" {
		respond(w, 200, map[string]any{"mapping_report": d.Mapping, "total_rows": len(d.Rows), "dataset_sha256": d.SHA256, "identity": Identity()})
		return
	}
	a.mu.RLock()
	c := a.config.Clone()
	a.mu.RUnlock()
	result, e := Analyze(r.Context(), d, c, a.options.MaxResults)
	if e != nil {
		failure(w, 400, e.Error())
		return
	}
	respond(w, 200, result)
}
