package approval

import (
	"errors"
	"testing"
	"time"

	"idvault/internal/rbac"
)

var (
	kasante   = rbac.Principal{Name: "kasante", Roles: []string{"restore_operator"}}
	gsantos   = rbac.Principal{Name: "gsantos", Roles: []string{"security_officer"}}
	rmalhotra = rbac.Principal{Name: "rmalhotra", Roles: []string{"security_officer"}}
)

func TestQuorum(t *testing.T) {
	m := NewManager(2, time.Hour)
	r := m.Create("restore", "planhash", "", "kasante")
	if _, err := m.Approve(r.ID, kasante); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator approval: %v", err)
	}
	selfish := m.Create("restore", "h", "", "gsantos")
	if _, err := m.Approve(selfish.ID, gsantos); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := m.Approve(r.ID, gsantos); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(r.ID, "restore", "planhash", "kasante"); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("consume with 1/2: %v", err)
	}
	if _, err := m.Approve(r.ID, gsantos); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := m.Approve(r.ID, rmalhotra); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(r.ID, "restore", "OTHER", "kasante"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if err := m.Consume(r.ID, "restore", "planhash", "kasante"); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(r.ID, "restore", "planhash", "kasante"); !errors.Is(err, ErrUsed) {
		t.Fatalf("replay: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	m := NewManager(1, time.Minute)
	m.Now = func() time.Time { return now }
	r := m.Create("restore", "h", "", "kasante")
	now = now.Add(2 * time.Minute)
	if _, err := m.Approve(r.ID, gsantos); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}
