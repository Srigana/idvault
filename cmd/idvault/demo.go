package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"idvault/internal/directory"
	"idvault/internal/policy"
)

// demo runs an incident against the real HTTP API in a temp directory.
// Each step uses whichever account would do it in real life.
func demo(_ []string) error {
	data, err := os.MkdirTemp("", "idvault-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(data)

	sys, err := build(data, policy.Defaults(), 2, true)
	if err != nil {
		return err
	}
	defer sys.Audit.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ts := httptest.NewServer(sys.server(quiet).Handler())
	defer ts.Close()
	c := &client{base: ts.URL, tokens: sys.Tokens}

	step("Accounts")
	for _, n := range []string{"amehta", "kasante", "gsantos", "hlindqvist"} {
		var me struct {
			Roles       []string `json:"roles"`
			Permissions []string `json:"permissions"`
		}
		c.do(n, "GET", "/v1/whoami", nil, &me)
		fmt.Printf("   %-11s %-17s %s\n", n, me.Roles[0], strings.Join(me.Permissions, ", "))
	}

	step("First snapshot")
	s0 := c.snapshot("svc-idvault")
	fmt.Printf("   %s  users=%d groups=%d new_objects=%d\n", s0.ID, s0.Stats.Users, s0.Stats.Groups, s0.Stats.NewObjects)

	step("Ordinary change: Daniel Cohen promoted")
	var dir directory.State
	c.do("hlindqvist", "GET", "/v1/directory", nil, &dir)
	u := dir.Users["u-010"]
	u.Attributes["title"] = "Head of Sales"
	c.do("hlindqvist", "PUT", "/v1/directory/users/u-010", u, nil)
	s1 := c.snapshot("svc-idvault")
	fmt.Printf("   %s  new_objects=%d reused=%d\n", s1.ID, s1.Stats.NewObjects, s1.Stats.ReusedObject)

	step("Attack: hlindqvist (helpdesk) is phished")
	for i := 1; i <= 25; i++ {
		c.do("hlindqvist", "DELETE", fmt.Sprintf("/v1/directory/users/u-%03d", i), nil, nil)
	}
	c.do("hlindqvist", "DELETE", "/v1/directory/groups/g-finance", nil, nil)
	c.do("hlindqvist", "DELETE", "/v1/directory/groups/g-hr", nil, nil)
	c.do("hlindqvist", "PUT", "/v1/directory/users/u-900", directory.User{Username: "svc-patchmgr", DisplayName: "Patch management", Enabled: true}, nil)
	c.do("hlindqvist", "PUT", "/v1/directory/groups/g-domain-admins/members/u-900", nil, nil)
	fmt.Println("   25 users and 2 groups deleted, svc-patchmgr created and added to Domain Admins")

	step("Attacker tries to delete the backups")
	code, msg := c.do("hlindqvist", "DELETE", "/v1/snapshots/"+s1.ID, nil, nil)
	fmt.Printf("   hlindqvist: %d %s\n", code, msg)
	code, msg = c.do("amehta", "DELETE", "/v1/snapshots/"+s1.ID, nil, nil)
	fmt.Printf("   amehta (backup_admin): %d %s\n", code, msg)

	step("Next snapshots")
	s2 := c.snapshot("svc-idvault")
	fmt.Printf("   %s  %s\n", s2.ID, s2.Status)
	for _, f := range s2.Findings {
		fmt.Printf("     %-8s %s\n", f.Severity, f.Message)
	}
	s3 := c.snapshot("svc-idvault")
	fmt.Printf("   %s  %s (nothing changed this hour, still flagged)\n", s3.ID, s3.Status)

	step("Last clean snapshot")
	var clean snap
	c.do("kasante", "GET", "/v1/snapshots/last-clean", nil, &clean)
	fmt.Printf("   %s\n", clean.ID)

	step("Preview: restore just Anil Mehta (u-001)")
	var gp plan
	c.do("kasante", "POST", "/v1/restores/plan", map[string]any{"snapshot_id": clean.ID, "mode": "merge", "scope": map[string]any{"users": []string{"u-001"}}}, &gp)
	for _, o := range gp.Ops {
		fmt.Printf("     %s\n", o)
	}
	for _, w := range gp.Warnings {
		fmt.Printf("     warning: %s\n", w)
	}

	step("Preview: full restore, exact mode")
	var fp plan
	c.do("kasante", "POST", "/v1/restores/plan", map[string]any{"snapshot_id": clean.ID, "mode": "exact"}, &fp)
	fmt.Printf("   %d ops %v, needs approval: %v\n", len(fp.Ops), fp.Counts, fp.Privileged)

	step("Run it")
	var pend struct {
		Status   string `json:"status"`
		Approval struct {
			ID string `json:"id"`
		} `json:"approval"`
	}
	code, _ = c.do("kasante", "POST", "/v1/restores", map[string]any{"snapshot_id": clean.ID, "mode": "exact"}, &pend)
	aid := pend.Approval.ID
	fmt.Printf("   kasante runs restore: %d %s, request %s\n", code, pend.Status, aid)
	code, msg = c.do("kasante", "POST", "/v1/approvals/"+aid+"/approve", nil, nil)
	fmt.Printf("   kasante approves it: %d %s\n", code, msg)
	code, _ = c.do("gsantos", "POST", "/v1/approvals/"+aid+"/approve", nil, nil)
	fmt.Printf("   gsantos approves: %d (1 of 2)\n", code)
	code, msg = c.do("gsantos", "POST", "/v1/approvals/"+aid+"/approve", nil, nil)
	fmt.Printf("   gsantos approves again: %d %s\n", code, msg)
	code, _ = c.do("rmalhotra", "POST", "/v1/approvals/"+aid+"/approve", nil, nil)
	fmt.Printf("   rmalhotra approves: %d (2 of 2)\n", code)

	var res struct {
		Status string `json:"status"`
		Result struct {
			Applied, Failed int
		} `json:"result"`
		Pre string `json:"pre_restore_snapshot"`
	}
	code, _ = c.do("kasante", "POST", "/v1/restores", map[string]any{"snapshot_id": clean.ID, "mode": "exact", "approval_id": aid}, &res)
	fmt.Printf("   kasante runs restore again: %d %s, applied=%d failed=%d, undo point %s\n", code, res.Status, res.Result.Applied, res.Result.Failed, res.Pre)

	step("Check the result")
	want, _ := sys.Engine.Load(clean.ID)
	got, _ := sys.Dir.Export(context.Background())
	_, backdoor := got.Users["u-900"]
	fmt.Printf("   matches %s: %v, svc-patchmgr still there: %v, users=%d groups=%d\n", clean.ID, directory.Diff(want, got).Empty(), backdoor, len(got.Users), len(got.Groups))
	s4 := c.snapshot("svc-idvault")
	fmt.Printf("   %s  %s\n", s4.ID, s4.Status)

	step("Single accidental deletion")
	c.do("hlindqvist", "DELETE", "/v1/directory/users/u-030", nil, nil)
	code, msg = c.do("kasante", "POST", "/v1/restores", map[string]any{"snapshot_id": s4.ID, "mode": "merge", "scope": map[string]any{"users": []string{"u-030"}}, "approval_id": aid}, nil)
	fmt.Printf("   reusing the old approval: %d %s\n", code, msg)
	var res2 struct {
		Status string                `json:"status"`
		Result struct{ Applied int } `json:"result"`
	}
	code, _ = c.do("kasante", "POST", "/v1/restores", map[string]any{"snapshot_id": s4.ID, "mode": "merge", "scope": map[string]any{"users": []string{"u-030"}}}, &res2)
	fmt.Printf("   restore u-030 (no privileged groups, no approval needed): %d %s, applied=%d\n", code, res2.Status, res2.Result.Applied)

	step("Tampering with a backup file")
	var vr struct {
		OK       bool     `json:"ok"`
		Objects  int      `json:"objects_checked"`
		Problems []string `json:"problems"`
	}
	c.do("taziz", "GET", "/v1/snapshots/"+s1.ID+"/verify", nil, &vr)
	fmt.Printf("   verify %s: ok=%v objects=%d\n", s1.ID, vr.OK, vr.Objects)
	m, _ := sys.Store.GetSnapshot(s1.ID)
	h := m.Entries["user/u-002"]
	objPath := filepath.Join(sys.Store.Root(), "objects", h[:2], h)
	_ = os.Chmod(objPath, 0o644)
	_ = os.WriteFile(objPath, []byte(`{"id":"u-002","username":"rdelgado2"}`), 0o644)
	c.do("taziz", "GET", "/v1/snapshots/"+s1.ID+"/verify", nil, &vr)
	fmt.Printf("   after editing one object on disk: ok=%v %v\n", vr.OK, vr.Problems)

	step("Audit log")
	var av struct {
		OK      bool `json:"ok"`
		Entries int  `json:"entries"`
	}
	c.do("taziz", "GET", "/v1/audit/verify", nil, &av)
	fmt.Printf("   chain ok=%v, %d entries. Denied requests:\n", av.OK, av.Entries)
	var entries []struct {
		Seq                            int
		Actor, Action, Outcome, Detail string
	}
	c.do("taziz", "GET", "/v1/audit", nil, &entries)
	for _, e := range entries {
		if e.Outcome == "denied" {
			fmt.Printf("     #%-3d %-11s %s\n", e.Seq, e.Actor, e.Detail)
		}
	}
	code, _ = c.do("hlindqvist", "GET", "/v1/audit", nil, nil)
	fmt.Printf("   hlindqvist reading the audit log: %d\n", code)
	return nil
}

type client struct {
	base   string
	tokens map[string]string
}

type finding struct{ Rule, Severity, Message string }
type snap struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Stats  struct {
		Users        int `json:"users"`
		Groups       int `json:"groups"`
		NewObjects   int `json:"new_objects"`
		ReusedObject int `json:"reused_objects"`
	} `json:"stats"`
	Findings []finding `json:"findings"`
}
type op struct {
	Kind    string `json:"kind"`
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
	Priv    bool   `json:"privileged"`
}

func (o op) String() string {
	s := o.Kind + " " + o.UserID
	if o.GroupID != "" {
		if o.UserID != "" {
			s += " in "
		}
		s += o.GroupID
	}
	if o.Priv {
		s += "  (privileged)"
	}
	return s
}

type plan struct {
	Ops        []op           `json:"ops"`
	Counts     map[string]int `json:"counts"`
	Privileged bool           `json:"privileged"`
	Warnings   []string       `json:"warnings"`
	Hash       string         `json:"hash"`
}

func (c *client) snapshot(who string) snap {
	var s snap
	if code, msg := c.do(who, "POST", "/v1/snapshots", map[string]string{"policy": "gold"}, &s); code != 201 {
		panic(fmt.Sprintf("snapshot failed: %d %s", code, msg))
	}
	return s
}

// do returns status code and error message (if any), decoding success bodies into out.
func (c *client) do(who, method, path string, body, out any) (int, string) {
	var rd io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else if method == "POST" || method == "PUT" {
		rd = strings.NewReader("{}")
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Authorization", "Bearer "+c.tokens[who])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode != 202 {
		var e struct{ Error string }
		_ = json.Unmarshal(b, &e)
		return resp.StatusCode, e.Error
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			panic(fmt.Sprintf("%s %s: %v", method, path, err))
		}
	}
	return resp.StatusCode, ""
}

func step(s string) { fmt.Printf("\n%s\n", s) }
