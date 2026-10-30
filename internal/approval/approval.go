// Package approval handles N-person approval for privileged restores.
//
// TODO: requests only live in memory, so a restart drops pending approvals.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"idvault/internal/rbac"
)

var (
	ErrNotFound     = errors.New("approval request not found")
	ErrSelfApproval = errors.New("requester cannot approve their own request")
	ErrDuplicate    = errors.New("principal already approved this request")
	ErrForbidden    = errors.New("principal lacks restore:approve")
	ErrExpired      = errors.New("approval request expired")
	ErrNotApproved  = errors.New("approval request does not have quorum")
	ErrMismatch     = errors.New("approval does not cover this action (plan changed since approval?)")
	ErrUsed         = errors.New("approval request already used")
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Consumed Status = "consumed"
)

type Vote struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

type Request struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Summary   string    `json:"summary"`
	Requester string    `json:"requester"`
	Required  int       `json:"required"`
	Approvals []Vote    `json:"approvals"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Manager struct {
	mu       sync.Mutex
	reqs     map[string]*Request
	Required int
	TTL      time.Duration
	Now      func() time.Time
}

func NewManager(required int, ttl time.Duration) *Manager {
	return &Manager{reqs: map[string]*Request{}, Required: required, TTL: ttl, Now: time.Now}
}

func (m *Manager) Create(action, resource, summary, requester string) *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now().UTC()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	r := &Request{
		ID: "apr-" + hex.EncodeToString(b), Action: action, Resource: resource, Summary: summary,
		Requester: requester, Required: m.Required, Approvals: []Vote{},
		Status: Pending, CreatedAt: now, ExpiresAt: now.Add(m.TTL),
	}
	m.reqs[r.ID] = r
	cp := *r
	return &cp
}

func (m *Manager) Approve(id string, p rbac.Principal) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	switch {
	case !ok:
		return nil, ErrNotFound
	case !p.Can(rbac.RestoreApprove):
		return nil, ErrForbidden
	case r.Status == Consumed:
		return nil, ErrUsed
	case m.Now().After(r.ExpiresAt):
		return nil, ErrExpired
	case p.Name == r.Requester:
		return nil, ErrSelfApproval
	}
	for _, v := range r.Approvals {
		if v.By == p.Name {
			return nil, ErrDuplicate
		}
	}
	r.Approvals = append(r.Approvals, Vote{By: p.Name, At: m.Now().UTC()})
	if len(r.Approvals) >= r.Required {
		r.Status = Approved
	}
	cp := *r
	return &cp, nil
}

// Consume marks the request used. The resource is the plan hash, so if the
// directory changed after approval the hash differs and this fails.
func (m *Manager) Consume(id, action, resource, requester string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	switch {
	case !ok:
		return ErrNotFound
	case r.Status == Consumed:
		return ErrUsed
	case m.Now().After(r.ExpiresAt):
		return ErrExpired
	case r.Status != Approved:
		return fmt.Errorf("%w (%d/%d)", ErrNotApproved, len(r.Approvals), r.Required)
	case r.Action != action || r.Resource != resource || r.Requester != requester:
		return ErrMismatch
	}
	r.Status = Consumed
	return nil
}

func (m *Manager) Get(id string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (m *Manager) List() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.reqs))
	for _, r := range m.reqs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
