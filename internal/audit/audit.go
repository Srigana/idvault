// Package audit is an append-only JSON-lines log where each entry stores the
// previous entry's hash.
//
// TODO: truncating the tail is only caught while the process is running
// (Verify compares against the in-memory count). Anchoring the latest hash
// somewhere external would fix that.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Outcome string    `json:"outcome"` // ok | denied | error
	Detail  string    `json:"detail,omitempty"`
	Prev    string    `json:"prev"`
	Hash    string    `json:"hash"`
}

func (e Entry) computeHash() string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Log struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	entries []Entry
	Now     func() time.Time
}

// Open loads and verifies an existing log, then opens it for appending.
func Open(path string) (*Log, error) {
	l := &Log{path: path, Now: time.Now}
	es, err := read(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := verify(es); err != nil {
		return nil, fmt.Errorf("audit log %s failed verification: %w", path, err)
	}
	l.entries = es
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Close() error { return l.f.Close() }

func (l *Log) Record(actor, action, target, outcome, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Seq: uint64(len(l.entries)) + 1, Time: l.Now().UTC(), Actor: actor, Action: action,
		Target: target, Outcome: outcome, Detail: detail, Prev: "genesis"}
	if n := len(l.entries); n > 0 {
		e.Prev = l.entries[n-1].Hash
	}
	e.Hash = e.computeHash()
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.entries = append(l.entries, e)
	return nil
}

func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// Verify re-reads the file from disk and checks the full chain.
func (l *Log) Verify() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	es, err := read(l.path)
	if err != nil {
		return 0, err
	}
	if len(es) < len(l.entries) {
		return len(es), fmt.Errorf("log truncated: %d entries on disk, %d expected", len(es), len(l.entries))
	}
	return len(es), verify(es)
}

func read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; sc.Scan(); line++ {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func verify(es []Entry) error {
	prev := "genesis"
	for i, e := range es {
		if e.Seq != uint64(i)+1 {
			return fmt.Errorf("entry %d: sequence gap (got %d)", i+1, e.Seq)
		}
		if e.Prev != prev {
			return fmt.Errorf("entry %d: chain broken", e.Seq)
		}
		if e.computeHash() != e.Hash {
			return fmt.Errorf("entry %d: content modified", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}
