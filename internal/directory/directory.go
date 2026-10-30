// Package directory is the identity store being backed up: users, groups and
// memberships. Directory is an in-memory stand-in for AD or Entra ID; an LDAP
// or Graph connector would implement Source and Writer instead.
package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var ErrNotFound = errors.New("not found")

type User struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	DisplayName string            `json:"display_name"`
	Email       string            `json:"email"`
	Enabled     bool              `json:"enabled"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Privileged  bool     `json:"privileged"` // e.g. Domain Admins: changes here are high-risk
	Members     []string `json:"members"`    // user IDs, sorted, unique
}

// SameMeta compares everything except Members.
func (g Group) SameMeta(o Group) bool {
	return g.ID == o.ID && g.Name == o.Name && g.Description == o.Description && g.Privileged == o.Privileged
}

type State struct {
	Users  map[string]User  `json:"users"`
	Groups map[string]Group `json:"groups"`
}

func NewState() State {
	return State{Users: map[string]User{}, Groups: map[string]Group{}}
}

func (s State) Clone() State {
	out := NewState()
	for id, u := range s.Users {
		out.Users[id] = cloneUser(u)
	}
	for id, g := range s.Groups {
		g.Members = append([]string(nil), g.Members...)
		out.Groups[id] = g
	}
	return out
}

func cloneUser(u User) User {
	if u.Attributes != nil {
		m := make(map[string]string, len(u.Attributes))
		for k, v := range u.Attributes {
			m[k] = v
		}
		u.Attributes = m
	}
	return u
}

type Source interface {
	Name() string
	Export(ctx context.Context) (State, error)
}

// Writer methods must be idempotent; restore relies on being able to re-run.
type Writer interface {
	UpsertUser(ctx context.Context, u User) error
	DeleteUser(ctx context.Context, id string) error
	UpsertGroup(ctx context.Context, g Group) error // metadata only; existing members preserved
	DeleteGroup(ctx context.Context, id string) error
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
}

// Directory persists to a JSON file when path is set.
type Directory struct {
	mu    sync.RWMutex
	name  string
	path  string
	state State
}

var (
	_ Source = (*Directory)(nil)
	_ Writer = (*Directory)(nil)
)

func New(name string) *Directory {
	return &Directory{name: name, state: NewState()}
}

// Open loads path, or writes seed() to it if the file doesn't exist yet.
func Open(name, path string, seed func() State) (*Directory, error) {
	d := &Directory{name: name, path: path}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		d.state = seed()
		return d, d.persistLocked()
	case err != nil:
		return nil, err
	}
	st := NewState()
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	d.state = st
	return d, nil
}

func (d *Directory) Name() string { return d.name }

func (d *Directory) Export(_ context.Context) (State, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.state.Clone(), nil
}

func (d *Directory) Load(s State) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = s.Clone()
	return d.persistLocked()
}

func (d *Directory) UpsertUser(_ context.Context, u User) error {
	if u.ID == "" {
		return errors.New("user id required")
	}
	return d.mutate(func(s *State) error {
		s.Users[u.ID] = cloneUser(u)
		return nil
	})
}

// DeleteUser also removes the user from every group, same as AD.
func (d *Directory) DeleteUser(_ context.Context, id string) error {
	return d.mutate(func(s *State) error {
		if _, ok := s.Users[id]; !ok {
			return nil
		}
		delete(s.Users, id)
		for gid, g := range s.Groups {
			g.Members = remove(g.Members, id)
			s.Groups[gid] = g
		}
		return nil
	})
}

func (d *Directory) UpsertGroup(_ context.Context, g Group) error {
	if g.ID == "" {
		return errors.New("group id required")
	}
	return d.mutate(func(s *State) error {
		if cur, ok := s.Groups[g.ID]; ok {
			g.Members = cur.Members
		} else {
			g.Members = []string{}
		}
		s.Groups[g.ID] = g
		return nil
	})
}

func (d *Directory) DeleteGroup(_ context.Context, id string) error {
	return d.mutate(func(s *State) error {
		delete(s.Groups, id)
		return nil
	})
}

func (d *Directory) AddMember(_ context.Context, groupID, userID string) error {
	return d.mutate(func(s *State) error {
		g, ok := s.Groups[groupID]
		if !ok {
			return fmt.Errorf("group %s: %w", groupID, ErrNotFound)
		}
		if _, ok := s.Users[userID]; !ok {
			return fmt.Errorf("user %s: %w", userID, ErrNotFound)
		}
		g.Members = insert(g.Members, userID)
		s.Groups[groupID] = g
		return nil
	})
}

func (d *Directory) RemoveMember(_ context.Context, groupID, userID string) error {
	return d.mutate(func(s *State) error {
		g, ok := s.Groups[groupID]
		if !ok {
			return nil
		}
		g.Members = remove(g.Members, userID)
		s.Groups[groupID] = g
		return nil
	})
}

func (d *Directory) mutate(fn func(*State) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := fn(&d.state); err != nil {
		return err
	}
	return d.persistLocked()
}

func (d *Directory) persistLocked() error {
	if d.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(d.state, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(d.path, b, 0o600)
}

// WriteFileAtomic writes to a temp file and renames it into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func insert(list []string, v string) []string {
	i := sort.SearchStrings(list, v)
	if i < len(list) && list[i] == v {
		return list
	}
	list = append(list, "")
	copy(list[i+1:], list[i:])
	list[i] = v
	return list
}

func remove(list []string, v string) []string {
	i := sort.SearchStrings(list, v)
	if i < len(list) && list[i] == v {
		return append(list[:i:i], list[i+1:]...)
	}
	return list
}

func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
