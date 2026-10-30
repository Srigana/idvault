// Package store keeps snapshot data on disk.
//
// Each user or group record is a file named by the SHA-256 of its JSON.
// A snapshot is a manifest listing those hashes, plus the hash of the
// previous manifest.
//
// TODO: the retention lock is enforced by this code only. Anyone with shell
// access on the host can still rm the files. S3 Object Lock would close that.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"idvault/internal/anomaly"
	"idvault/internal/directory"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrExists    = errors.New("already exists (write-once)")
	ErrImmutable = errors.New("snapshot is under retention lock")
	ErrCorrupt   = errors.New("integrity check failed")
)

type Status string

const (
	StatusClean      Status = "clean"
	StatusSuspicious Status = "suspicious"
)

type Stats struct {
	Users        int `json:"users"`
	Groups       int `json:"groups"`
	NewObjects   int `json:"new_objects"`
	ReusedObject int `json:"reused_objects"`
	BytesWritten int `json:"bytes_written"`
}

type Manifest struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	Policy      string            `json:"policy"`
	CreatedAt   time.Time         `json:"created_at"`
	LockedUntil time.Time         `json:"locked_until"`
	ExpiresAt   time.Time         `json:"expires_at"`
	ParentID    string            `json:"parent_id,omitempty"`
	ParentHash  string            `json:"parent_hash,omitempty"`
	Entries     map[string]string `json:"entries"` // "user/<id>" | "group/<id>" -> object hash
	Stats       Stats             `json:"stats"`
	Changes     directory.Changes `json:"changes"`
	Status      Status            `json:"status"`
	Findings    []anomaly.Finding `json:"findings,omitempty"`
	Hash        string            `json:"hash"`
}

func (m Manifest) ComputeHash() string {
	m.Hash = ""
	b, _ := json.Marshal(m)
	return sum(b)
}

type Store struct {
	root string
	mu   sync.Mutex
}

func Open(root string) (*Store, error) {
	for _, d := range []string{"objects", "snapshots"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *Store) objPath(h string) string {
	return filepath.Join(s.root, "objects", h[:2], h)
}

func (s *Store) snapPath(id string) string {
	return filepath.Join(s.root, "snapshots", id+".json")
}

// created is false when the object was already there.
func (s *Store) PutObject(data []byte) (hash string, created bool, err error) {
	hash = sum(data)
	p := s.objPath(hash)
	if _, err := os.Stat(p); err == nil {
		return hash, false, nil
	}
	if err := directory.WriteFileAtomic(p, data, 0o444); err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// GetObject re-hashes on every read so a corrupted file is never returned.
func (s *Store) GetObject(hash string) ([]byte, error) {
	if len(hash) != 64 {
		return nil, fmt.Errorf("bad hash %q", hash)
	}
	b, err := os.ReadFile(s.objPath(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("object %s: %w", hash[:12], ErrNotFound)
	} else if err != nil {
		return nil, err
	}
	if sum(b) != hash {
		return nil, fmt.Errorf("object %s: %w", hash[:12], ErrCorrupt)
	}
	return b, nil
}

func (s *Store) PutSnapshot(m *Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.snapPath(m.ID)
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("snapshot %s: %w", m.ID, ErrExists)
	}
	m.Hash = m.ComputeHash()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return directory.WriteFileAtomic(p, b, 0o444)
}

func (s *Store) GetSnapshot(id string) (*Manifest, error) {
	if strings.ContainsAny(id, `/\.`) || id == "" {
		return nil, fmt.Errorf("bad snapshot id %q", id)
	}
	b, err := os.ReadFile(s.snapPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("snapshot %s: %w", id, ErrNotFound)
	} else if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("snapshot %s: %w: %v", id, ErrCorrupt, err)
	}
	return &m, nil
}

// List is oldest first.
func (s *Store) List() ([]*Manifest, error) {
	ents, err := os.ReadDir(filepath.Join(s.root, "snapshots"))
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		m, err := s.GetSnapshot(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Delete only removes the manifest; GC reclaims the objects later.
func (s *Store) Delete(id string, now time.Time) error {
	m, err := s.GetSnapshot(id)
	if err != nil {
		return err
	}
	if now.Before(m.LockedUntil) {
		return fmt.Errorf("snapshot %s locked until %s: %w", id, m.LockedUntil.Format(time.RFC3339), ErrImmutable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(s.snapPath(id))
}

func (s *Store) GC() (removed int, err error) {
	ms, err := s.List()
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for _, m := range ms {
		for _, h := range m.Entries {
			live[h] = true
		}
	}
	err = filepath.WalkDir(filepath.Join(s.root, "objects"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !live[d.Name()] && !strings.HasPrefix(d.Name(), ".tmp") {
			if err := os.Remove(p); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

type VerifyReport struct {
	SnapshotID string   `json:"snapshot_id"`
	OK         bool     `json:"ok"`
	Objects    int      `json:"objects_checked"`
	Problems   []string `json:"problems,omitempty"`
}

func (s *Store) Verify(id string) VerifyReport {
	r := VerifyReport{SnapshotID: id}
	m, err := s.GetSnapshot(id)
	if err != nil {
		r.Problems = append(r.Problems, err.Error())
		return r
	}
	if got := m.ComputeHash(); got != m.Hash {
		r.Problems = append(r.Problems, "manifest hash mismatch: manifest was modified after it was written")
	}
	if m.ParentID != "" {
		if p, err := s.GetSnapshot(m.ParentID); err == nil && p.Hash != m.ParentHash {
			r.Problems = append(r.Problems, "parent hash mismatch: chain broken at "+m.ParentID)
		}
		// A missing parent is fine, it may have been pruned.
	}
	for _, k := range directory.SortedKeys(m.Entries) {
		r.Objects++
		if _, err := s.GetObject(m.Entries[k]); err != nil {
			r.Problems = append(r.Problems, k+": "+err.Error())
		}
	}
	r.OK = len(r.Problems) == 0
	return r
}

func (s *Store) Root() string { return s.root }

// Triage lets a security officer overrule the detector. Manifests can't be
// edited, so verdicts go in a separate file.
type Triage struct {
	Status Status    `json:"status"`
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

func (s *Store) triagePath() string { return filepath.Join(s.root, "triage.json") }

func (s *Store) Triages() (map[string]Triage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.triagesLocked()
}

func (s *Store) triagesLocked() (map[string]Triage, error) {
	out := map[string]Triage{}
	b, err := os.ReadFile(s.triagePath())
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(b, &out)
}

func (s *Store) SetTriage(id string, t Triage) error {
	if _, err := s.GetSnapshot(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.triagesLocked()
	if err != nil {
		return err
	}
	all[id] = t
	b, _ := json.MarshalIndent(all, "", "  ")
	return directory.WriteFileAtomic(s.triagePath(), b, 0o600)
}

func (s *Store) EffectiveStatus(m *Manifest) Status {
	if t, err := s.Triages(); err == nil {
		if v, ok := t[m.ID]; ok {
			return v.Status
		}
	}
	return m.Status
}
