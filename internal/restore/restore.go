// Package restore builds and runs restore plans.
package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"idvault/internal/directory"
)

type Mode string

const (
	// Merge brings back missing or changed objects and never deletes anything.
	Merge Mode = "merge"
	// Exact also removes things added after the snapshot. Users and groups are
	// only deleted on a full restore; a scoped restore only removes memberships.
	Exact Mode = "exact"
)

// Scope limits a restore. Empty scope means the whole directory.
type Scope struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

func (s Scope) Full() bool { return len(s.Users) == 0 && len(s.Groups) == 0 }

type Request struct {
	SnapshotID string `json:"snapshot_id"`
	Scope      Scope  `json:"scope"`
	Mode       Mode   `json:"mode"`
}

type OpKind string

const (
	CreateUser   OpKind = "create_user"
	UpdateUser   OpKind = "update_user"
	CreateGroup  OpKind = "create_group"
	UpdateGroup  OpKind = "update_group"
	AddMember    OpKind = "add_member"
	RemoveMember OpKind = "remove_member"
	DeleteGroup  OpKind = "delete_group"
	DeleteUser   OpKind = "delete_user"
)

// Users and groups have to exist before memberships can point at them.
var phase = map[OpKind]int{
	CreateUser: 0, UpdateUser: 0, CreateGroup: 1, UpdateGroup: 1,
	AddMember: 2, RemoveMember: 3, DeleteGroup: 4, DeleteUser: 5,
}

type Op struct {
	Kind       OpKind `json:"kind"`
	UserID     string `json:"user_id,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
}

func (o Op) String() string {
	switch {
	case o.UserID != "" && o.GroupID != "":
		return fmt.Sprintf("%s %s -> %s", o.Kind, o.UserID, o.GroupID)
	case o.UserID != "":
		return fmt.Sprintf("%s %s", o.Kind, o.UserID)
	default:
		return fmt.Sprintf("%s %s", o.Kind, o.GroupID)
	}
}

type Plan struct {
	SnapshotID string   `json:"snapshot_id"`
	Mode       Mode     `json:"mode"`
	Scope      Scope    `json:"scope"`
	Ops        []Op     `json:"ops"`
	Privileged bool     `json:"privileged"` // touches privileged groups -> needs quorum
	Warnings   []string `json:"warnings,omitempty"`
	Hash       string   `json:"hash"`
}

func (p *Plan) Counts() map[OpKind]int {
	c := map[OpKind]int{}
	for _, o := range p.Ops {
		c[o.Kind]++
	}
	return c
}

// Build computes the plan to move current toward target for req.
func Build(target, current directory.State, req Request) (*Plan, error) {
	if req.Mode == "" {
		req.Mode = Merge
	}
	if req.Mode != Merge && req.Mode != Exact {
		return nil, fmt.Errorf("unknown mode %q", req.Mode)
	}
	full := req.Scope.Full()
	scopeU, scopeG := set(req.Scope.Users), set(req.Scope.Groups)
	for id := range scopeU {
		if _, ok := target.Users[id]; !ok {
			return nil, fmt.Errorf("user %s is not in snapshot %s", id, req.SnapshotID)
		}
	}
	for id := range scopeG {
		if _, ok := target.Groups[id]; !ok {
			return nil, fmt.Errorf("group %s is not in snapshot %s", id, req.SnapshotID)
		}
	}
	deleteExtras := req.Mode == Exact && full
	p := &Plan{SnapshotID: req.SnapshotID, Mode: req.Mode, Scope: req.Scope, Ops: []Op{}}

	inScopeU := func(id string) bool { return full || scopeU[id] }
	inScopeG := func(id string) bool { return full || scopeG[id] }
	userWillExist := func(id string) bool {
		_, inT := target.Users[id]
		_, inC := current.Users[id]
		if inScopeU(id) && inT {
			return true
		}
		return inC && !(deleteExtras && !inT)
	}
	groupWillExist := func(id string) bool {
		_, inT := target.Groups[id]
		_, inC := current.Groups[id]
		if inScopeG(id) && inT {
			return true
		}
		return inC && !(deleteExtras && !inT)
	}
	privileged := func(gid string) bool {
		return target.Groups[gid].Privileged || current.Groups[gid].Privileged
	}

	for _, id := range union(target.Users, current.Users) {
		if !inScopeU(id) {
			continue
		}
		t, inT := target.Users[id]
		c, inC := current.Users[id]
		switch {
		case inT && !inC:
			p.Ops = append(p.Ops, Op{Kind: CreateUser, UserID: id})
		case inT && inC && !reflect.DeepEqual(norm(t), norm(c)):
			p.Ops = append(p.Ops, Op{Kind: UpdateUser, UserID: id})
		case !inT && inC && deleteExtras:
			p.Ops = append(p.Ops, Op{Kind: DeleteUser, UserID: id})
		}
	}
	for _, id := range union(target.Groups, current.Groups) {
		if !inScopeG(id) {
			continue
		}
		t, inT := target.Groups[id]
		c, inC := current.Groups[id]
		switch {
		case inT && !inC:
			p.Ops = append(p.Ops, Op{Kind: CreateGroup, GroupID: id, Privileged: t.Privileged})
		case inT && inC && !t.SameMeta(c):
			p.Ops = append(p.Ops, Op{Kind: UpdateGroup, GroupID: id, Privileged: privileged(id)})
		case !inT && inC && deleteExtras:
			p.Ops = append(p.Ops, Op{Kind: DeleteGroup, GroupID: id, Privileged: c.Privileged})
		}
	}
	// Memberships. Restoring a single user also puts it back in its groups.
	warned := map[string]bool{}
	for _, gid := range union(target.Groups, current.Groups) {
		tm, cm := set(target.Groups[gid].Members), set(current.Groups[gid].Members)
		if !groupWillExist(gid) {
			for uid := range tm {
				if scopeU[uid] && !warned[gid] {
					warned[gid] = true
					p.Warnings = append(p.Warnings, fmt.Sprintf("group %s no longer exists; add it to scope to restore memberships in it", gid))
				}
			}
			continue
		}
		_, groupExistsNow := current.Groups[gid]
		for _, uid := range keys(tm, cm) {
			if !(full || scopeG[gid] || scopeU[uid]) {
				continue
			}
			if !userWillExist(uid) {
				if tm[uid] && scopeG[gid] {
					p.Warnings = append(p.Warnings, fmt.Sprintf("member %s of %s no longer exists; add it to scope to restore it", uid, gid))
				}
				continue
			}
			want, have := tm[uid], groupExistsNow && cm[uid]
			switch {
			case want && !have:
				p.Ops = append(p.Ops, Op{Kind: AddMember, GroupID: gid, UserID: uid, Privileged: privileged(gid)})
			case !want && have && req.Mode == Exact:
				p.Ops = append(p.Ops, Op{Kind: RemoveMember, GroupID: gid, UserID: uid, Privileged: privileged(gid)})
			}
		}
	}

	sort.SliceStable(p.Ops, func(i, j int) bool { return phase[p.Ops[i].Kind] < phase[p.Ops[j].Kind] })
	for _, o := range p.Ops {
		if o.Privileged {
			p.Privileged = true
		}
	}
	p.Hash = hashPlan(p)
	return p, nil
}

func hashPlan(p *Plan) string {
	b, _ := json.Marshal(struct {
		S string
		M Mode
		O []Op
	}{p.SnapshotID, p.Mode, p.Ops})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Result struct {
	Applied int      `json:"applied"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

// Execute keeps going after a failed op. Every op is idempotent, so the fix
// for a partial failure is to plan and run again.
func Execute(ctx context.Context, w directory.Writer, target directory.State, p *Plan) (Result, error) {
	var r Result
	for _, o := range p.Ops {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		var err error
		switch o.Kind {
		case CreateUser, UpdateUser:
			err = w.UpsertUser(ctx, target.Users[o.UserID])
		case CreateGroup, UpdateGroup:
			err = w.UpsertGroup(ctx, target.Groups[o.GroupID])
		case AddMember:
			err = w.AddMember(ctx, o.GroupID, o.UserID)
		case RemoveMember:
			err = w.RemoveMember(ctx, o.GroupID, o.UserID)
		case DeleteGroup:
			err = w.DeleteGroup(ctx, o.GroupID)
		case DeleteUser:
			err = w.DeleteUser(ctx, o.UserID)
		default:
			err = fmt.Errorf("unknown op %s", o.Kind)
		}
		if err != nil {
			r.Failed++
			r.Errors = append(r.Errors, o.String()+": "+err.Error())
			continue
		}
		r.Applied++
	}
	if r.Failed > 0 {
		return r, errors.New("restore completed with errors")
	}
	return r, nil
}

func norm(u directory.User) directory.User {
	if len(u.Attributes) == 0 {
		u.Attributes = nil
	}
	return u
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func union[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var out []string
	for k := range a {
		seen[k] = true
		out = append(out, k)
	}
	for k := range b {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func keys(a, b map[string]bool) []string { return union(a, b) }
