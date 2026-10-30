package restore

import (
	"context"
	"testing"

	"idvault/internal/directory"
)

func attack(t *testing.T) (target directory.State, d *directory.Directory) {
	t.Helper()
	ctx := context.Background()
	target = directory.Seed()
	d = directory.New("t")
	_ = d.Load(target)
	for _, id := range []string{"u-001", "u-002", "u-007"} {
		_ = d.DeleteUser(ctx, id)
	}
	_ = d.DeleteGroup(ctx, "g-hr")
	_ = d.UpsertUser(ctx, directory.User{ID: "u-900", Username: "backdoor", Enabled: true})
	_ = d.AddMember(ctx, "g-domain-admins", "u-900")
	return target, d
}

func TestGranularUserRestoreBringsBackMemberships(t *testing.T) {
	target, d := attack(t)
	cur, _ := d.Export(context.Background())
	p, err := Build(target, cur, Request{SnapshotID: "s", Mode: Merge, Scope: Scope{Users: []string{"u-001"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"create_user u-001": true}
	for _, g := range target.Groups {
		for _, m := range g.Members {
			if m == "u-001" {
				want["add_member u-001 -> "+g.ID] = true
			}
		}
	}
	if len(want) < 3 || len(p.Ops) != len(want) {
		t.Fatalf("ops = %v, want %v", p.Ops, want)
	}
	for _, o := range p.Ops {
		if !want[o.String()] {
			t.Fatalf("unexpected op %s", o)
		}
	}
	if !p.Privileged {
		t.Fatal("re-adding to Domain Admins must be privileged")
	}
	// Backdoor untouched by a granular merge.
	for _, o := range p.Ops {
		if o.UserID == "u-900" {
			t.Fatal("granular restore touched out-of-scope user")
		}
	}
}

func TestGranularWarnsAboutMissingGroup(t *testing.T) {
	target, d := attack(t)
	cur, _ := d.Export(context.Background())
	// u-007's department group (hr) was deleted.
	p, _ := Build(target, cur, Request{Mode: Merge, Scope: Scope{Users: []string{"u-007"}}})
	if len(p.Warnings) == 0 {
		t.Fatal("expected a warning about deleted group g-hr")
	}
	p, _ = Build(target, cur, Request{Mode: Merge, Scope: Scope{Users: []string{"u-007"}, Groups: []string{"g-hr"}}})
	if len(p.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", p.Warnings)
	}
}

func TestExactFullRestoreConvergesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	target, d := attack(t)
	cur, _ := d.Export(ctx)
	p, err := Build(target, cur, Request{SnapshotID: "s", Mode: Exact})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, d, target, p); err != nil {
		t.Fatal(err)
	}
	after, _ := d.Export(ctx)
	if ch := directory.Diff(target, after); !ch.Empty() {
		t.Fatalf("not converged: %+v", ch)
	}
	p2, _ := Build(target, after, Request{SnapshotID: "s", Mode: Exact})
	if len(p2.Ops) != 0 {
		t.Fatalf("second plan should be empty, got %v", p2.Ops)
	}
}

func TestMergeKeepsExtras(t *testing.T) {
	ctx := context.Background()
	target, d := attack(t)
	cur, _ := d.Export(ctx)
	p, _ := Build(target, cur, Request{Mode: Merge})
	_, _ = Execute(ctx, d, target, p)
	after, _ := d.Export(ctx)
	if _, ok := after.Users["u-900"]; !ok {
		t.Fatal("merge must not delete")
	}
}

func TestPlanHashDeterministic(t *testing.T) {
	target, d := attack(t)
	cur, _ := d.Export(context.Background())
	a, _ := Build(target, cur, Request{SnapshotID: "s", Mode: Exact})
	b, _ := Build(target, cur, Request{SnapshotID: "s", Mode: Exact})
	if a.Hash != b.Hash {
		t.Fatal("plan hash not deterministic")
	}
}

func TestScopeValidation(t *testing.T) {
	target, d := attack(t)
	cur, _ := d.Export(context.Background())
	if _, err := Build(target, cur, Request{Scope: Scope{Users: []string{"u-900"}}}); err == nil {
		t.Fatal("restoring a user absent from the snapshot must fail")
	}
}

func TestEmptyPlanHasEmptyOpsNotNil(t *testing.T) {
	s := directory.Seed()
	p, _ := Build(s, s, Request{Mode: Exact})
	if p.Ops == nil {
		t.Fatal("Ops must be an empty slice so it encodes as [] for API clients")
	}
}
