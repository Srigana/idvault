// Package snapshot takes snapshots and loads them back.
//
// TODO: Load decodes every object. For a large forest it would be better to
// diff two manifests by hash and only decode what changed.
package snapshot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"idvault/internal/anomaly"
	"idvault/internal/directory"
	"idvault/internal/policy"
	"idvault/internal/store"
)

type Engine struct {
	Store    *store.Store
	Source   directory.Source
	Detector anomaly.Detector
	Now      func() time.Time

	mu sync.Mutex // one snapshot at a time keeps the parent chain linear
}

func New(st *store.Store, src directory.Source) *Engine {
	return &Engine{Store: st, Source: src, Detector: anomaly.DefaultDetector(), Now: func() time.Time { return time.Now().UTC() }}
}

func (e *Engine) Take(ctx context.Context, p policy.Policy) (*store.Manifest, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cur, err := e.Source.Export(ctx)
	if err != nil {
		return nil, fmt.Errorf("export %s: %w", e.Source.Name(), err)
	}
	now := e.Now().UTC()
	m := &store.Manifest{
		ID:          newID(now),
		Source:      e.Source.Name(),
		Policy:      p.Name,
		CreatedAt:   now,
		LockedUntil: now.Add(p.Lock.Duration),
		ExpiresAt:   now.Add(p.Retention.Duration),
		Entries:     map[string]string{},
		Status:      store.StatusClean,
	}

	// Unchanged records hash the same, so PutObject skips them.
	put := func(key string, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		h, created, err := e.Store.PutObject(b)
		if err != nil {
			return err
		}
		m.Entries[key] = h
		if created {
			m.Stats.NewObjects++
			m.Stats.BytesWritten += len(b)
		} else {
			m.Stats.ReusedObject++
		}
		return nil
	}
	for _, id := range directory.SortedKeys(cur.Users) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := put("user/"+id, cur.Users[id]); err != nil {
			return nil, err
		}
	}
	for _, id := range directory.SortedKeys(cur.Groups) {
		if err := put("group/"+id, cur.Groups[id]); err != nil {
			return nil, err
		}
	}
	m.Stats.Users, m.Stats.Groups = len(cur.Users), len(cur.Groups)

	parent, err := e.Latest()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if parent != nil {
		prev, err := e.Load(parent.ID)
		if err != nil {
			return nil, fmt.Errorf("load parent %s: %w", parent.ID, err)
		}
		m.ParentID, m.ParentHash = parent.ID, parent.Hash
		m.Changes = directory.Diff(prev, cur)
		m.Findings = e.Detector.Analyze(prev, cur, m.Changes)
		// Comparing against a suspicious parent was wrong both ways: an hour
		// with no changes after an attack came out "clean", and the restore
		// itself got flagged as privilege escalation. Compare against the last
		// clean snapshot instead.
		if e.Store.EffectiveStatus(parent) == store.StatusSuspicious {
			if base, err := e.LastClean(); err == nil {
				if bs, err := e.Load(base.ID); err == nil {
					m.Findings = nil
					for _, f := range e.Detector.Analyze(bs, cur, directory.Diff(bs, cur)) {
						f.Message += ", compared with the last clean snapshot"
						m.Findings = append(m.Findings, f)
					}
				}
			}
		}
		if anomaly.Suspicious(m.Findings) {
			m.Status = store.StatusSuspicious
		}
	}
	if err := e.Store.PutSnapshot(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (e *Engine) Load(id string) (directory.State, error) {
	m, err := e.Store.GetSnapshot(id)
	if err != nil {
		return directory.State{}, err
	}
	if m.ComputeHash() != m.Hash {
		return directory.State{}, fmt.Errorf("snapshot %s: %w", id, store.ErrCorrupt)
	}
	st := directory.NewState()
	for key, h := range m.Entries {
		b, err := e.Store.GetObject(h)
		if err != nil {
			return directory.State{}, fmt.Errorf("%s: %w", key, err)
		}
		kind, oid, _ := strings.Cut(key, "/")
		switch kind {
		case "user":
			var u directory.User
			if err := json.Unmarshal(b, &u); err != nil {
				return directory.State{}, err
			}
			st.Users[oid] = u
		case "group":
			var g directory.Group
			if err := json.Unmarshal(b, &g); err != nil {
				return directory.State{}, err
			}
			if g.Members == nil {
				g.Members = []string{}
			}
			st.Groups[oid] = g
		default:
			return directory.State{}, fmt.Errorf("unknown entry kind %q", key)
		}
	}
	return st, nil
}

func (e *Engine) Latest() (*store.Manifest, error) {
	ms, err := e.Store.List()
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, store.ErrNotFound
	}
	return ms[len(ms)-1], nil
}

// LastClean skips pre-restore snapshots: they capture the broken state.
func (e *Engine) LastClean() (*store.Manifest, error) {
	ms, err := e.Store.List()
	if err != nil {
		return nil, err
	}
	for i := len(ms) - 1; i >= 0; i-- {
		if e.Store.EffectiveStatus(ms[i]) == store.StatusClean && ms[i].Policy != PreRestorePolicy.Name {
			return ms[i], nil
		}
	}
	return nil, fmt.Errorf("no clean snapshot: %w", store.ErrNotFound)
}

// Prune never deletes the newest snapshot, even if it has expired.
func (e *Engine) Prune() (deleted []string, objects int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ms, err := e.Store.List()
	if err != nil {
		return nil, 0, err
	}
	now := e.Now()
	for i, m := range ms {
		if i == len(ms)-1 || now.Before(m.ExpiresAt) {
			continue
		}
		if err := e.Store.Delete(m.ID, now); err != nil {
			return deleted, 0, err
		}
		deleted = append(deleted, m.ID)
	}
	objects, err = e.Store.GC()
	return deleted, objects, err
}

var PreRestorePolicy = policy.Policy{
	Name:      "pre-restore",
	Frequency: policy.D(time.Hour),
	Retention: policy.D(7 * 24 * time.Hour),
	Lock:      policy.D(24 * time.Hour),
}

func newID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("snap-%s%03dZ-%s", t.Format("20060102T150405"), t.Nanosecond()/1e6, hex.EncodeToString(b))
}
