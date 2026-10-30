// Package api is the HTTP/JSON API and serves the web console.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"idvault/internal/approval"
	"idvault/internal/audit"
	"idvault/internal/directory"
	"idvault/internal/policy"
	"idvault/internal/rbac"
	"idvault/internal/restore"
	"idvault/internal/snapshot"
	"idvault/internal/store"
)

type Server struct {
	Dir       *directory.Directory
	Engine    *snapshot.Engine
	Auth      *rbac.Authenticator
	Approvals *approval.Manager
	Audit     *audit.Log
	Policies  []policy.Policy
	Log       *slog.Logger
	Dev       bool // fixed tokens and a sign-in picker in the console; never in production
}

type ctxKey struct{}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "dev": s.Dev, "source": s.Dir.Name()})
	})
	s.routeUI(mux)
	if s.Dev {
		mux.HandleFunc("GET /v1/dev/principals", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, rbac.DemoPrincipals())
		})
	}

	h := func(pattern, action string, perm rbac.Permission, fn func(http.ResponseWriter, *http.Request, rbac.Principal)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			p, ok := s.Auth.Authenticate(tok)
			if !ok {
				_ = s.Audit.Record("anonymous", action, r.URL.Path, "denied", "unauthenticated")
				writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
			if perm != "" && !p.Can(perm) {
				_ = s.Audit.Record(p.Name, action, r.URL.Path, "denied", "missing "+string(perm))
				writeErr(w, http.StatusForbidden, fmt.Sprintf("%s lacks permission %s", p.Name, perm))
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, p))
			fn(w, r, p)
		})
	}

	h("GET /v1/whoami", "whoami", "", s.whoami) // any authenticated principal
	h("GET /v1/policies", "policy.list", rbac.PolicyRead, func(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) { writeJSON(w, 200, s.Policies) })

	h("GET /v1/directory", "directory.read", rbac.DirectoryRead, s.getDirectory)
	h("PUT /v1/directory/users/{id}", "directory.user.put", rbac.DirectoryWrite, s.putUser)
	h("DELETE /v1/directory/users/{id}", "directory.user.delete", rbac.DirectoryWrite, s.deleteUser)
	h("DELETE /v1/directory/groups/{id}", "directory.group.delete", rbac.DirectoryWrite, s.deleteGroup)
	h("PUT /v1/directory/groups/{id}/members/{uid}", "directory.member.add", rbac.DirectoryWrite, s.addMember)

	h("POST /v1/snapshots", "snapshot.create", rbac.SnapshotCreate, s.createSnapshot)
	h("GET /v1/snapshots", "snapshot.list", rbac.SnapshotRead, s.listSnapshots)
	h("GET /v1/snapshots/last-clean", "snapshot.last_clean", rbac.SnapshotRead, s.lastClean)
	h("GET /v1/snapshots/{id}", "snapshot.read", rbac.SnapshotRead, s.getSnapshot)
	h("GET /v1/snapshots/{id}/verify", "snapshot.verify", rbac.SnapshotRead, s.verifySnapshot)
	h("GET /v1/snapshots/{id}/contents", "snapshot.contents", rbac.SnapshotRead, s.snapshotContents)
	h("POST /v1/snapshots/{id}/triage", "snapshot.triage", rbac.SnapshotTriage, s.triageSnapshot)
	h("DELETE /v1/snapshots/{id}", "snapshot.delete", rbac.SnapshotDelete, s.deleteSnapshot)

	h("POST /v1/restores/plan", "restore.plan", rbac.RestorePlan, s.planRestore)
	h("POST /v1/restores", "restore.execute", rbac.RestoreExecute, s.executeRestore)

	h("GET /v1/approvals", "approval.list", rbac.SnapshotRead, func(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) { writeJSON(w, 200, s.Approvals.List()) })
	h("POST /v1/approvals/{id}/approve", "approval.approve", rbac.RestoreApprove, s.approve)

	h("GET /v1/audit", "audit.read", rbac.AuditRead, func(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) { writeJSON(w, 200, s.Audit.Entries()) })
	h("GET /v1/audit/verify", "audit.verify", rbac.AuditRead, s.verifyAudit)

	return s.logging(mux)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, code: 200}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(rw, r)
		if s.Log != nil {
			s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rw.code, "dur", time.Since(start))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func (s *Server) whoami(w http.ResponseWriter, _ *http.Request, p rbac.Principal) {
	writeJSON(w, 200, map[string]any{"name": p.Name, "roles": p.Roles, "permissions": p.Permissions()})
}

func (s *Server) getDirectory(w http.ResponseWriter, r *http.Request, _ rbac.Principal) {
	st, err := s.Dir.Export(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) putUser(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	var u directory.User
	if !decode(w, r, &u) {
		return
	}
	u.ID = r.PathValue("id")
	s.mutate(w, p, "directory.user.put", u.ID, s.Dir.UpsertUser(r.Context(), u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	id := r.PathValue("id")
	s.mutate(w, p, "directory.user.delete", id, s.Dir.DeleteUser(r.Context(), id))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	id := r.PathValue("id")
	s.mutate(w, p, "directory.group.delete", id, s.Dir.DeleteGroup(r.Context(), id))
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	gid, uid := r.PathValue("id"), r.PathValue("uid")
	s.mutate(w, p, "directory.member.add", gid+"/"+uid, s.Dir.AddMember(r.Context(), gid, uid))
}

func (s *Server) mutate(w http.ResponseWriter, p rbac.Principal, action, target string, err error) {
	if err != nil {
		_ = s.Audit.Record(p.Name, action, target, "error", err.Error())
		code := 500
		if errors.Is(err, directory.ErrNotFound) {
			code = 404
		}
		writeErr(w, code, err.Error())
		return
	}
	_ = s.Audit.Record(p.Name, action, target, "ok", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) policy(name string) (policy.Policy, bool) {
	for _, p := range s.Policies {
		if p.Name == name {
			return p, true
		}
	}
	return policy.Policy{}, false
}

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	var req struct {
		Policy string `json:"policy"`
	}
	if !decode(w, r, &req) {
		return
	}
	pol, ok := s.policy(req.Policy)
	if !ok {
		writeErr(w, 400, "unknown policy "+req.Policy)
		return
	}
	m, err := s.Engine.Take(r.Context(), pol)
	if err != nil {
		_ = s.Audit.Record(p.Name, "snapshot.create", pol.Name, "error", err.Error())
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.Audit.Record(p.Name, "snapshot.create", m.ID, "ok", string(m.Status))
	writeJSON(w, 201, summarize(s.Engine.Store, m, true))
}

type snapView struct {
	ID          string             `json:"id"`
	Policy      string             `json:"policy"`
	CreatedAt   time.Time          `json:"created_at"`
	LockedUntil time.Time          `json:"locked_until"`
	ExpiresAt   time.Time          `json:"expires_at"`
	ParentID    string             `json:"parent_id,omitempty"`
	Hash        string             `json:"hash"`
	Status      store.Status       `json:"status"`
	Detected    store.Status       `json:"detected_status"`
	Stats       store.Stats        `json:"stats"`
	Changed     int                `json:"changed"`
	Triage      *store.Triage      `json:"triage,omitempty"`
	Findings    any                `json:"findings,omitempty"`
	Changes     *directory.Changes `json:"changes,omitempty"`
}

func summarize(st *store.Store, m *store.Manifest, detail bool) snapView {
	v := snapView{ID: m.ID, Policy: m.Policy, CreatedAt: m.CreatedAt, LockedUntil: m.LockedUntil,
		ExpiresAt: m.ExpiresAt, ParentID: m.ParentID, Hash: m.Hash, Status: st.EffectiveStatus(m),
		Detected: m.Status, Stats: m.Stats, Changed: countChanges(m.Changes)}
	if len(m.Findings) > 0 {
		v.Findings = m.Findings
	}
	if t, err := st.Triages(); err == nil {
		if tr, ok := t[m.ID]; ok {
			v.Triage = &tr
		}
	}
	if detail {
		v.Changes = &m.Changes
	}
	return v
}

func countChanges(c directory.Changes) int {
	return len(c.UsersAdded) + len(c.UsersDeleted) + len(c.UsersModified) +
		len(c.GroupsAdded) + len(c.GroupsDeleted) + len(c.GroupsModified) +
		len(c.MembershipAdded) + len(c.MembershipRemoved)
}

func (s *Server) snapshotContents(w http.ResponseWriter, r *http.Request, _ rbac.Principal) {
	st, err := s.Engine.Load(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) listSnapshots(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) {
	ms, err := s.Engine.Store.List()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]snapView, 0, len(ms))
	for _, m := range ms {
		out = append(out, summarize(s.Engine.Store, m, false))
	}
	writeJSON(w, 200, out)
}

func (s *Server) getSnapshot(w http.ResponseWriter, r *http.Request, _ rbac.Principal) {
	m, err := s.Engine.Store.GetSnapshot(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, summarize(s.Engine.Store, m, true))
}

func (s *Server) lastClean(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) {
	m, err := s.Engine.LastClean()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, summarize(s.Engine.Store, m, false))
}

func (s *Server) verifySnapshot(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	rep := s.Engine.Store.Verify(r.PathValue("id"))
	outcome := "ok"
	if !rep.OK {
		outcome = "error"
	}
	_ = s.Audit.Record(p.Name, "snapshot.verify", rep.SnapshotID, outcome, strings.Join(rep.Problems, "; "))
	writeJSON(w, 200, rep)
}

func (s *Server) triageSnapshot(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	var req struct {
		Status store.Status `json:"status"`
		Reason string       `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if (req.Status != store.StatusClean && req.Status != store.StatusSuspicious) || req.Reason == "" {
		writeErr(w, 400, "status must be clean|suspicious and reason is required")
		return
	}
	id := r.PathValue("id")
	err := s.Engine.Store.SetTriage(id, store.Triage{Status: req.Status, By: p.Name, Reason: req.Reason, At: time.Now().UTC()})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.Audit.Record(p.Name, "snapshot.triage", id, "ok", string(req.Status)+": "+req.Reason)
	w.WriteHeader(204)
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	id := r.PathValue("id")
	err := s.Engine.Store.Delete(id, s.Engine.Now())
	if err != nil {
		_ = s.Audit.Record(p.Name, "snapshot.delete", id, "denied", err.Error())
		writeStoreErr(w, err)
		return
	}
	_ = s.Audit.Record(p.Name, "snapshot.delete", id, "ok", "")
	w.WriteHeader(204)
}

type restoreReq struct {
	restore.Request
	ApprovalID string `json:"approval_id,omitempty"`
}

func (s *Server) buildPlan(ctx context.Context, req restore.Request) (*restore.Plan, directory.State, error) {
	target, err := s.Engine.Load(req.SnapshotID)
	if err != nil {
		return nil, target, err
	}
	cur, err := s.Dir.Export(ctx)
	if err != nil {
		return nil, target, err
	}
	p, err := restore.Build(target, cur, req)
	return p, target, err
}

type planView struct {
	*restore.Plan
	Counts map[restore.OpKind]int `json:"counts"`
}

func (s *Server) planRestore(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	var req restoreReq
	if !decode(w, r, &req) {
		return
	}
	plan, _, err := s.buildPlan(r.Context(), req.Request)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.Audit.Record(p.Name, "restore.plan", req.SnapshotID, "ok", fmt.Sprintf("%d ops, privileged=%v", len(plan.Ops), plan.Privileged))
	writeJSON(w, 200, planView{plan, plan.Counts()})
}

func (s *Server) executeRestore(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	var req restoreReq
	if !decode(w, r, &req) {
		return
	}
	plan, target, err := s.buildPlan(r.Context(), req.Request)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if len(plan.Ops) == 0 {
		writeJSON(w, 200, map[string]any{"status": "noop", "plan": planView{plan, plan.Counts()}})
		return
	}
	// Check an approval_id even when the plan doesn't need one, otherwise a
	// used approval would be silently ignored instead of rejected.
	if plan.Privileged || req.ApprovalID != "" {
		if req.ApprovalID == "" {
			ar := s.Approvals.Create("restore", plan.Hash,
				fmt.Sprintf("restore %s (%s), %d ops", plan.SnapshotID, plan.Mode, len(plan.Ops)), p.Name)
			_ = s.Audit.Record(p.Name, "restore.request_approval", ar.ID, "ok", ar.Summary)
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status": "approval_required", "approval": ar, "plan": planView{plan, plan.Counts()},
			})
			return
		}
		if err := s.Approvals.Consume(req.ApprovalID, "restore", plan.Hash, p.Name); err != nil {
			_ = s.Audit.Record(p.Name, "restore.execute", req.ApprovalID, "denied", err.Error())
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// Snapshot the current state first so the restore can be undone.
	pre, err := s.Engine.Take(r.Context(), snapshot.PreRestorePolicy)
	if err != nil {
		writeErr(w, 500, "pre-restore snapshot failed, aborting: "+err.Error())
		return
	}
	res, err := restore.Execute(r.Context(), s.Dir, target, plan)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	_ = s.Audit.Record(p.Name, "restore.execute", plan.SnapshotID, outcome,
		fmt.Sprintf("applied=%d failed=%d pre_restore=%s approval=%s", res.Applied, res.Failed, pre.ID, req.ApprovalID))
	code := 200
	if err != nil {
		code = 207
	}
	writeJSON(w, code, map[string]any{"status": outcome, "result": res, "pre_restore_snapshot": pre.ID, "plan_hash": plan.Hash})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, p rbac.Principal) {
	id := r.PathValue("id")
	ar, err := s.Approvals.Approve(id, p)
	if err != nil {
		_ = s.Audit.Record(p.Name, "approval.approve", id, "denied", err.Error())
		code := 409
		if errors.Is(err, approval.ErrNotFound) {
			code = 404
		} else if errors.Is(err, approval.ErrSelfApproval) || errors.Is(err, approval.ErrForbidden) {
			code = 403
		}
		writeErr(w, code, err.Error())
		return
	}
	_ = s.Audit.Record(p.Name, "approval.approve", id, "ok", fmt.Sprintf("%d/%d", len(ar.Approvals), ar.Required))
	writeJSON(w, 200, ar)
}

func (s *Server) verifyAudit(w http.ResponseWriter, _ *http.Request, _ rbac.Principal) {
	n, err := s.Audit.Verify()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "entries": n, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "entries": n})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, store.ErrImmutable):
		writeErr(w, 409, err.Error())
	case errors.Is(err, store.ErrCorrupt):
		writeErr(w, 422, err.Error())
	default:
		writeErr(w, 400, err.Error())
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
