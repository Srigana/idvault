package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"idvault/internal/directory"
	"idvault/internal/policy"
	"idvault/internal/store"
)

var gold = policy.Policy{Name: "gold", Frequency: policy.D(time.Hour), Retention: policy.D(48 * time.Hour), Lock: policy.D(24 * time.Hour)}

func setup(t *testing.T) (*Engine, *directory.Directory) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := directory.New("test")
	if err := dir.Load(directory.Seed()); err != nil {
		t.Fatal(err)
	}
	return New(st, dir), dir
}

func TestIncrementalDedup(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	s0, err := e.Take(ctx, gold)
	if err != nil {
		t.Fatal(err)
	}
	seed := directory.Seed()
	total := len(seed.Users) + len(seed.Groups)
	if s0.Stats.NewObjects != total || s0.Stats.ReusedObject != 0 {
		t.Fatalf("baseline stats: %+v", s0.Stats)
	}
	u := directory.Seed().Users["u-005"]
	u.Attributes["title"] = "Manager"
	_ = dir.UpsertUser(ctx, u)
	s1, _ := e.Take(ctx, gold)
	if s1.Stats.NewObjects != 1 || s1.Stats.ReusedObject != total-1 {
		t.Fatalf("incremental stats: %+v", s1.Stats)
	}
	if s1.ParentID != s0.ID || s1.ParentHash != s0.Hash {
		t.Fatal("chain not linked")
	}
	got, err := e.Load(s0.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !directory.Diff(directory.Seed(), got).Empty() {
		t.Fatal("round-trip of baseline is not exact")
	}
}

func TestAnomalyAndLastClean(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	s0, _ := e.Take(ctx, gold)
	for _, id := range []string{"u-001", "u-002", "u-003", "u-004", "u-005", "u-006", "u-007", "u-008", "u-009", "u-010", "u-011", "u-012", "u-013"} {
		_ = dir.DeleteUser(ctx, id)
	}
	s1, _ := e.Take(ctx, gold)
	if s1.Status != store.StatusSuspicious {
		t.Fatalf("expected suspicious, got %s %+v", s1.Status, s1.Findings)
	}
	s2, _ := e.Take(ctx, gold) // no further changes
	if s2.Status != store.StatusSuspicious {
		t.Fatal("compromise laundered by a quiet interval")
	}
	lc, err := e.LastClean()
	if err != nil || lc.ID != s0.ID {
		t.Fatalf("last clean = %v %v, want %s", lc, err, s0.ID)
	}
	// Triage can override a false positive.
	if err := e.Store.SetTriage(s1.ID, store.Triage{Status: store.StatusClean, By: "gsantos", Reason: "planned offboarding"}); err != nil {
		t.Fatal(err)
	}
	if e.Store.EffectiveStatus(s1) != store.StatusClean {
		t.Fatal("triage not applied")
	}
}

func TestPrivilegeEscalationDetected(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	_, _ = e.Take(ctx, gold)
	_ = dir.AddMember(ctx, "g-domain-admins", "u-050")
	s1, _ := e.Take(ctx, gold)
	if s1.Status != store.StatusSuspicious || s1.Findings[0].Rule != "privileged_membership_added" {
		t.Fatalf("got %s %+v", s1.Status, s1.Findings)
	}
}

func TestRetentionLockAndPrune(t *testing.T) {
	e, _ := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { return now }
	s0, _ := e.Take(ctx, gold)
	now = now.Add(time.Hour)
	_, _ = e.Take(ctx, gold)

	if err := e.Store.Delete(s0.ID, now); !errors.Is(err, store.ErrImmutable) {
		t.Fatalf("delete inside lock: %v", err)
	}
	now = now.Add(72 * time.Hour) // past retention
	del, _, err := e.Prune()
	if err != nil || len(del) != 1 || del[0] != s0.ID {
		t.Fatalf("prune = %v %v", del, err)
	}
	ms, _ := e.Store.List()
	if len(ms) != 1 {
		t.Fatal("newest snapshot must always survive")
	}
	if r := e.Store.Verify(ms[0].ID); !r.OK {
		t.Fatalf("snapshot with expired parent should verify: %+v", r)
	}
}

func TestTamperDetection(t *testing.T) {
	e, _ := setup(t)
	s0, _ := e.Take(context.Background(), gold)

	h := s0.Entries["group/g-domain-admins"]
	p := filepath.Join(e.Store.Root(), "objects", h[:2], h)
	_ = os.Chmod(p, 0o644)
	if err := os.WriteFile(p, []byte(`{"id":"g-domain-admins","members":["u-666"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := e.Store.Verify(s0.ID); r.OK {
		t.Fatal("tampered object not detected")
	}
	if _, err := e.Load(s0.ID); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("restore source must refuse corrupt data, got %v", err)
	}

	// Manifest tampering.
	mp := filepath.Join(e.Store.Root(), "snapshots", s0.ID+".json")
	b, _ := os.ReadFile(mp)
	_ = os.Chmod(mp, 0o644)
	_ = os.WriteFile(mp, append(b[:len(b)-2], []byte(`,"x":1}`)...), 0o644)
	m, _ := e.Store.GetSnapshot(s0.ID)
	m.LockedUntil = time.Time{}
	if m.ComputeHash() == m.Hash {
		t.Fatal("manifest edit not detected")
	}
}
