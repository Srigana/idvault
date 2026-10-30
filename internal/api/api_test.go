package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"idvault/internal/approval"
	"idvault/internal/audit"
	"idvault/internal/directory"
	"idvault/internal/policy"
	"idvault/internal/rbac"
	"idvault/internal/snapshot"
	"idvault/internal/store"
)

type env struct {
	ts  *httptest.Server
	dir *directory.Directory
}

func newEnv(t *testing.T) *env {
	t.Helper()
	tmp := t.TempDir()
	st, _ := store.Open(filepath.Join(tmp, "vault"))
	dir := directory.New("test")
	_ = dir.Load(directory.Seed())
	auth := rbac.NewAuthenticator()
	for _, p := range rbac.DemoPrincipals() {
		_ = auth.Add("tok-"+p.Name, p)
	}
	al, err := audit.Open(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	s := &Server{Dir: dir, Engine: snapshot.New(st, dir), Auth: auth, Approvals: approval.NewManager(2, time.Hour),
		Audit: al, Policies: policy.Defaults(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &env{ts, dir}
}

func (e *env) call(t *testing.T, who, method, path string, body any, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	if body == nil {
		b = []byte("{}")
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(b))
	if who != "" {
		req.Header.Set("Authorization", "Bearer tok-"+who)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAuthz(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		who, method, path string
		want              int
	}{
		{"", "GET", "/v1/snapshots", 401},
		{"nobody", "GET", "/v1/snapshots", 401},
		{"hlindqvist", "GET", "/v1/snapshots", 403},
		{"hlindqvist", "POST", "/v1/restores", 403},
		{"kasante", "GET", "/v1/audit", 403},
		{"taziz", "GET", "/v1/audit", 200},
		{"amehta", "POST", "/v1/approvals/x/approve", 403},
		{"hlindqvist", "GET", "/v1/whoami", 200},
	}
	for _, c := range cases {
		if got := e.call(t, c.who, c.method, c.path, nil, nil); got != c.want {
			t.Errorf("%s %s %s = %d, want %d", c.who, c.method, c.path, got, c.want)
		}
	}
}

func TestApprovalBoundToPlan(t *testing.T) {
	e := newEnv(t)
	var s0 struct{ ID string }
	if c := e.call(t, "svc-idvault", "POST", "/v1/snapshots", map[string]string{"policy": "gold"}, &s0); c != 201 {
		t.Fatalf("snapshot: %d", c)
	}
	e.call(t, "hlindqvist", "DELETE", "/v1/directory/users/u-001", nil, nil)

	req := map[string]any{"snapshot_id": s0.ID, "mode": "exact"}
	var pend struct {
		Approval struct{ ID string } `json:"approval"`
	}
	if c := e.call(t, "kasante", "POST", "/v1/restores", req, &pend); c != 202 {
		t.Fatalf("expected 202, got %d", c)
	}
	e.call(t, "gsantos", "POST", "/v1/approvals/"+pend.Approval.ID+"/approve", nil, nil)
	e.call(t, "rmalhotra", "POST", "/v1/approvals/"+pend.Approval.ID+"/approve", nil, nil)

	// State drifts after approval: the approved plan no longer matches.
	e.call(t, "hlindqvist", "DELETE", "/v1/directory/users/u-002", nil, nil)
	req["approval_id"] = pend.Approval.ID
	if c := e.call(t, "kasante", "POST", "/v1/restores", req, nil); c != 403 {
		t.Fatalf("drifted plan must be refused, got %d", c)
	}
	// Someone else cannot use kasante's approval.
	if c := e.call(t, "gsantos", "POST", "/v1/restores", req, nil); c != 403 {
		t.Fatalf("gsantos lacks restore:execute, got %d", c)
	}
}

func TestRetentionLockViaAPI(t *testing.T) {
	e := newEnv(t)
	var s0 struct{ ID string }
	e.call(t, "svc-idvault", "POST", "/v1/snapshots", map[string]string{"policy": "gold"}, &s0)
	if c := e.call(t, "amehta", "DELETE", "/v1/snapshots/"+s0.ID, nil, nil); c != 409 {
		t.Fatalf("locked delete = %d", c)
	}
	var v struct{ OK bool }
	e.call(t, "taziz", "GET", "/v1/audit/verify", nil, &v)
	if !v.OK {
		t.Fatal("audit chain broken")
	}
}
