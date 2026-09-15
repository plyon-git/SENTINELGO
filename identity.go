// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const Owner = "Parrish Lyon"
const Watermark = "PL-SENTINELGO-20260914"
const Version = "1.0.0"
const SourceCommit = "ad9a0a62455da2a0eb432bfa3747b5ba2a0afe9c"

type BuildIdentity struct {
	Owner          string `json:"owner"`
	Watermark      string `json:"watermark"`
	Version        string `json:"version"`
	SourceCommit   string `json:"source_commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

//go:embed WATERMARK.json
var baseline []byte

//go:embed web/*
var assets embed.FS

func Identity() BuildIdentity {
	return BuildIdentity{Owner, Watermark, Version, SourceCommit, fmt.Sprintf("%x", sha256.Sum256(baseline))}
}

type Manifest struct {
	Owner     string            `json:"owner"`
	Watermark string            `json:"watermark"`
	Files     map[string]string `json:"files"`
}

// Verify checks listed source files against the manifest embedded at compilation.
// It is tamper evidence relative to this binary, not an external signature/DRM.
func Verify(root string) error {
	var m Manifest
	if e := json.Unmarshal(baseline, &m); e != nil {
		return e
	}
	if m.Owner != Owner || m.Watermark != Watermark || len(m.Files) == 0 {
		return fmt.Errorf("invalid embedded watermark baseline")
	}
	disk, e := os.ReadFile(filepath.Join(root, "WATERMARK.json"))
	if e != nil {
		return e
	}
	if !bytes.Equal(disk, baseline) {
		return fmt.Errorf("manifest differs from compiled baseline")
	}
	names := make([]string, 0, len(m.Files))
	for name := range m.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "." || path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, "\\") || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe manifest path")
		}
		parts := strings.Split(name, "/")
		candidate := root
		for _, part := range parts {
			candidate = filepath.Join(candidate, part)
			info, e := os.Lstat(candidate)
			if e != nil {
				return fmt.Errorf("missing %s", name)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink rejected: %s", name)
			}
		}
		f, e := os.Open(candidate)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if fmt.Sprintf("%x", h.Sum(nil)) != m.Files[name] {
			return fmt.Errorf("integrity mismatch: %s", name)
		}
	}
	return nil
}
