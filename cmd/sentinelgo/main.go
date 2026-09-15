// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	sentinel "github.com/plyon-git/SENTINELGO"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentinelgo <serve|analyze|generate|verify|version> [flags]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "version":
		return json.NewEncoder(os.Stdout).Encode(sentinel.Identity())
	case "verify":
		f := flag.NewFlagSet("verify", flag.ContinueOnError)
		root := f.String("root", ".", "source directory to verify")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if e := sentinel.Verify(*root); e != nil {
			return e
		}
		fmt.Println("Verified: Parrish Lyon | " + sentinel.Watermark)
		return nil
	case "generate":
		f := flag.NewFlagSet("generate", flag.ContinueOnError)
		rows := f.Int("rows", 200000, "number of synthetic orders (max 1000000)")
		seed := f.Int64("seed", 1, "deterministic pseudo-random seed")
		end := f.String("end", time.Now().UTC().Format(time.RFC3339), "end of 90-day window (RFC3339)")
		output := f.String("output", "realistic_orders.csv", "new CSV path; existing files are not overwritten")
		labels := f.Bool("labels", false, "include synthetic is_fraud label; analyzer ignores it")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		t, e := time.Parse(time.RFC3339, *end)
		if e != nil {
			return e
		}
		return writeNew(*output, func(w io.Writer) error {
			s, e := sentinel.Generate(ctx, w, sentinel.GenerateOptions{Rows: *rows, Seed: *seed, End: t, Labels: *labels})
			if e == nil {
				_ = json.NewEncoder(os.Stderr).Encode(s)
			}
			return e
		})
	case "analyze":
		f := flag.NewFlagSet("analyze", flag.ContinueOnError)
		input := f.String("input", "", "input CSV")
		output := f.String("output", "-", "new JSON path, or - for stdout")
		limit := f.Int("max-results", 5000, "maximum flagged records in JSON (counts remain complete)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *input == "" {
			return fmt.Errorf("-input is required")
		}
		file, e := os.Open(*input)
		if e != nil {
			return e
		}
		defer file.Close()
		d, e := sentinel.ReadCSV(ctx, file, sentinel.MaxRows)
		if e != nil {
			return e
		}
		result, e := sentinel.Analyze(ctx, d, sentinel.DefaultConfig(), *limit)
		if e != nil {
			return e
		}
		write := func(w io.Writer) error { enc := json.NewEncoder(w); enc.SetIndent("", "  "); return enc.Encode(result) }
		if *output == "-" {
			return write(os.Stdout)
		}
		return writeNew(*output, write)
	case "serve":
		f := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := f.String("addr", "127.0.0.1:8080", "listen address")
		limit := f.Int("max-results", 5000, "maximum flagged records per response")
		verify := f.Bool("verify", false, "verify source baseline before starting")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *verify {
			if e := sentinel.Verify("."); e != nil {
				return e
			}
		}
		key := os.Getenv("SENTINEL_API_TOKEN")
		if !sentinel.LocalAddress(*addr) && key == "" {
			return fmt.Errorf("non-loopback binding requires SENTINEL_API_TOKEN (32+ bytes)")
		}
		handler, e := sentinel.NewHandler(sentinel.ServerOptions{APIKey: key, AdminKey: os.Getenv("SENTINEL_ADMIN_TOKEN"), MaxResults: *limit})
		if e != nil {
			return e
		}
		server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 3 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if e := server.Shutdown(c); e != nil {
					_ = server.Close()
				}
			case <-done:
			}
		}()
		defer close(done)
		log.Printf("SENTINELGO %s | %s | %s | http://%s", sentinel.Version, sentinel.Owner, sentinel.Watermark, *addr)
		e = server.ListenAndServe()
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

// Fail rather than overwriting existing data, and remove incomplete outputs.
func writeNew(name string, write func(io.Writer) error) error {
	f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if e = write(f); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
