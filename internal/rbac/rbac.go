// Package rbac has the roles and token auth for the idvault API.
package rbac

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"idvault/internal/directory"
)

type Permission string

const (
	DirectoryRead  Permission = "directory:read"
	DirectoryWrite Permission = "directory:write"
	SnapshotCreate Permission = "snapshot:create"
	SnapshotRead   Permission = "snapshot:read"
	SnapshotDelete Permission = "snapshot:delete"
	SnapshotTriage Permission = "snapshot:triage"
	RestorePlan    Permission = "restore:plan"
	RestoreExecute Permission = "restore:execute"
	RestoreApprove Permission = "restore:approve"
	PolicyRead     Permission = "policy:read"
	AuditRead      Permission = "audit:read"
)

// directory_admin deliberately has no backup permissions: if a helpdesk
// account is phished, the attacker still can't touch snapshots.
var Roles = map[string][]Permission{
	"backup_admin":     {SnapshotCreate, SnapshotRead, SnapshotDelete, PolicyRead, RestorePlan, AuditRead},
	"backup_operator":  {SnapshotCreate, SnapshotRead, PolicyRead},
	"restore_operator": {SnapshotRead, RestorePlan, RestoreExecute, DirectoryRead},
	"security_officer": {SnapshotRead, SnapshotTriage, RestorePlan, RestoreApprove, AuditRead, DirectoryRead},
	"auditor":          {SnapshotRead, AuditRead, PolicyRead},
	"directory_admin":  {DirectoryRead, DirectoryWrite},
}

type Principal struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

func (p Principal) Can(perm Permission) bool {
	for _, r := range p.Roles {
		for _, x := range Roles[r] {
			if x == perm {
				return true
			}
		}
	}
	return false
}

func (p Principal) Permissions() []string {
	seen := map[Permission]bool{}
	for _, r := range p.Roles {
		for _, x := range Roles[r] {
			seen[x] = true
		}
	}
	out := make([]string, 0, len(seen))
	for x := range seen {
		out = append(out, string(x))
	}
	sort.Strings(out)
	return out
}

// Authenticator stores SHA-256 digests of tokens, never the tokens.
type Authenticator struct {
	mu      sync.RWMutex
	digests map[string]Principal
}

func NewAuthenticator() *Authenticator { return &Authenticator{digests: map[string]Principal{}} }

func digest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (a *Authenticator) Add(token string, p Principal) error {
	for _, r := range p.Roles {
		if _, ok := Roles[r]; !ok {
			return fmt.Errorf("unknown role %q", r)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.digests[digest(token)] = p
	return nil
}

// Looking up by digest is fine timing-wise: an attacker can't choose the
// digest, so learning how many leading bytes matched tells them nothing.
func (a *Authenticator) Authenticate(token string) (Principal, bool) {
	if token == "" {
		return Principal{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	p, ok := a.digests[digest(token)]
	return p, ok
}

type principalRecord struct {
	TokenSHA256 string `json:"token_sha256"`
	Principal
}

// LoadOrInit reads principals from path. On first run it creates them with
// random tokens and returns the plaintext tokens so serve can print them once.
func LoadOrInit(path string) (*Authenticator, map[string]string, error) {
	a := NewAuthenticator()
	b, err := os.ReadFile(path)
	if err == nil {
		var recs []principalRecord
		if err := json.Unmarshal(b, &recs); err != nil {
			return nil, nil, err
		}
		for _, r := range recs {
			a.digests[r.TokenSHA256] = r.Principal
		}
		return a, nil, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	tokens := map[string]string{}
	var recs []principalRecord
	for _, spec := range DemoPrincipals() {
		t := randomToken()
		tokens[spec.Name] = t
		recs = append(recs, principalRecord{digest(t), spec})
		a.digests[digest(t)] = spec
	}
	out, _ := json.MarshalIndent(recs, "", "  ")
	return a, tokens, directory.WriteFileAtomic(path, out, 0o600)
}

// DemoPrincipals are the console users created on first start. They map to
// people in the sample directory.
func DemoPrincipals() []Principal {
	return []Principal{
		{Name: "amehta", Roles: []string{"backup_admin"}},
		{Name: "kasante", Roles: []string{"restore_operator"}},
		{Name: "gsantos", Roles: []string{"security_officer"}},
		{Name: "rmalhotra", Roles: []string{"security_officer"}},
		{Name: "taziz", Roles: []string{"auditor"}},
		{Name: "hlindqvist", Roles: []string{"directory_admin"}},
		{Name: "svc-idvault", Roles: []string{"backup_operator"}},
	}
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "idv_" + hex.EncodeToString(b)
}
