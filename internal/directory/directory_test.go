package directory

import (
	"context"
	"testing"
)

func TestDeleteUserStripsMemberships(t *testing.T) {
	d := New("t")
	_ = d.Load(Seed())
	_ = d.DeleteUser(context.Background(), "u-001")
	st, _ := d.Export(context.Background())
	for _, g := range st.Groups {
		for _, m := range g.Members {
			if m == "u-001" {
				t.Fatalf("u-001 still in %s", g.ID)
			}
		}
	}
	ch := Diff(Seed(), st)
	if len(ch.UsersDeleted) != 1 || len(ch.MembershipRemoved) == 0 {
		t.Fatalf("diff = %+v", ch)
	}
}

func TestExportIsACopy(t *testing.T) {
	d := New("t")
	_ = d.Load(Seed())
	st, _ := d.Export(context.Background())
	st.Users["u-001"].Attributes["title"] = "CEO"
	again, _ := d.Export(context.Background())
	if again.Users["u-001"].Attributes["title"] == "CEO" {
		t.Fatal("Export leaked internal state")
	}
}
