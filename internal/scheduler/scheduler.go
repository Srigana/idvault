// Package scheduler takes snapshots on each policy's interval and prunes old ones.
package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"idvault/internal/audit"
	"idvault/internal/policy"
	"idvault/internal/snapshot"
	"idvault/internal/store"
)

type Scheduler struct {
	Engine   *snapshot.Engine
	Policies []policy.Policy
	Audit    *audit.Log
	Log      *slog.Logger
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range s.Policies {
		wg.Add(1)
		go func(p policy.Policy) {
			defer wg.Done()
			t := time.NewTicker(p.Frequency.Duration)
			defer t.Stop()
			for {
				s.RunOnce(ctx, p)
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}(p)
	}
	wg.Wait()
}

func (s *Scheduler) RunOnce(ctx context.Context, p policy.Policy) {
	m, err := s.Engine.Take(ctx, p)
	if err != nil {
		s.Log.Error("snapshot failed", "policy", p.Name, "err", err)
		_ = s.Audit.Record("scheduler", "snapshot.create", p.Name, "error", err.Error())
		return
	}
	s.Log.Info("snapshot taken", "id", m.ID, "policy", p.Name, "status", m.Status,
		"new_objects", m.Stats.NewObjects, "reused", m.Stats.ReusedObject)
	_ = s.Audit.Record("scheduler", "snapshot.create", m.ID, "ok", string(m.Status))
	if m.Status == store.StatusSuspicious {
		for _, f := range m.Findings {
			s.Log.Warn("ANOMALY", "snapshot", m.ID, "rule", f.Rule, "severity", f.Severity, "msg", f.Message)
		}
	}
	if del, objs, err := s.Engine.Prune(); err != nil {
		s.Log.Error("prune failed", "err", err)
	} else if len(del) > 0 {
		s.Log.Info("expired snapshots pruned", "snapshots", len(del), "objects", objs)
		_ = s.Audit.Record("scheduler", "snapshot.prune", "", "ok", "")
	}
}
