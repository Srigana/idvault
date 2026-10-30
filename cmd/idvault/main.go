// Command idvault backs up and restores directory users and groups.
//
//	idvault serve [-addr :8080] [-data ./data] [-policies policies.json] [-dev]
//	idvault demo
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"idvault/internal/api"
	"idvault/internal/approval"
	"idvault/internal/audit"
	"idvault/internal/directory"
	"idvault/internal/policy"
	"idvault/internal/rbac"
	"idvault/internal/scheduler"
	"idvault/internal/snapshot"
	"idvault/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "demo":
		err = demo(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: idvault serve [-addr :8080] [-data ./data] [-policies file.json] [-dev] | idvault demo")
	os.Exit(2)
}

type System struct {
	Dir       *directory.Directory
	Store     *store.Store
	Engine    *snapshot.Engine
	Auth      *rbac.Authenticator
	Approvals *approval.Manager
	Audit     *audit.Log
	Policies  []policy.Policy
	Tokens    map[string]string // only set on first init, or in dev mode
	DataDir   string
	Dev       bool
}

func build(dataDir string, policies []policy.Policy, quorum int, dev bool) (*System, error) {
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	dir, err := directory.Open("harbourline.local", filepath.Join(dataDir, "directory.json"), directory.Seed)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(dataDir, "vault"))
	if err != nil {
		return nil, err
	}
	var auth *rbac.Authenticator
	var tokens map[string]string
	if dev {
		auth, tokens = rbac.NewAuthenticator(), map[string]string{}
		for _, p := range rbac.DemoPrincipals() {
			tokens[p.Name] = "dev-" + p.Name
			_ = auth.Add(tokens[p.Name], p)
		}
	} else if auth, tokens, err = rbac.LoadOrInit(filepath.Join(dataDir, "principals.json")); err != nil {
		return nil, err
	}
	al, err := audit.Open(filepath.Join(dataDir, "audit.log"))
	if err != nil {
		return nil, err
	}
	return &System{
		Dir: dir, Store: st, Engine: snapshot.New(st, dir), Auth: auth,
		Approvals: approval.NewManager(quorum, 30*time.Minute), Audit: al,
		Policies: policies, Tokens: tokens, DataDir: dataDir, Dev: dev,
	}, nil
}

func (s *System) server(log *slog.Logger) *api.Server {
	return &api.Server{Dir: s.Dir, Engine: s.Engine, Auth: s.Auth, Approvals: s.Approvals,
		Audit: s.Audit, Policies: s.Policies, Log: log, Dev: s.Dev}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	data := fs.String("data", "./data", "data directory")
	polFile := fs.String("policies", "", "JSON file with SLA policies (default: built-in gold/silver)")
	quorum := fs.Int("quorum", 2, "approvals required for privileged restores")
	dev := fs.Bool("dev", false, "use fixed tokens (dev-<name>) and enable the sign-in picker. Local use only")
	_ = fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	pols := policy.Defaults()
	if *polFile != "" {
		b, err := os.ReadFile(*polFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &pols); err != nil {
			return fmt.Errorf("parse %s: %w", *polFile, err)
		}
	}
	sys, err := build(*data, pols, *quorum, *dev)
	if err != nil {
		return err
	}
	defer sys.Audit.Close()
	if *dev {
		fmt.Println("Dev mode: tokens are dev-<name>. Don't expose this server to a network.")
	} else if sys.Tokens != nil {
		fmt.Println("First start: generated API tokens (shown once, only hashes are stored):")
		for _, p := range rbac.DemoPrincipals() {
			fmt.Printf("  %-10s %-18s %s\n", p.Name, p.Roles[0], sys.Tokens[p.Name])
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sched := &scheduler.Scheduler{Engine: sys.Engine, Policies: sys.Policies, Audit: sys.Audit, Log: log}
	go sched.Run(ctx)

	srv := &http.Server{Addr: *addr, Handler: sys.server(log).Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("idvault listening", "addr", *addr, "data", *data)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("shut down cleanly")
	return nil
}
