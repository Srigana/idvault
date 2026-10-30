// Package policy holds backup schedules: frequency, retention and lock period.
package policy

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Policy struct {
	Name      string   `json:"name"`
	Frequency Duration `json:"frequency"`
	Retention Duration `json:"retention"`
	Lock      Duration `json:"lock"` // snapshot cannot be deleted by anyone before this elapses
}

func (p Policy) Validate() error {
	switch {
	case p.Name == "":
		return fmt.Errorf("policy name required")
	case p.Frequency.Duration <= 0:
		return fmt.Errorf("policy %s: frequency must be > 0", p.Name)
	case p.Retention.Duration < p.Lock.Duration:
		return fmt.Errorf("policy %s: retention must be >= lock", p.Name)
	}
	return nil
}

func D(d time.Duration) Duration { return Duration{d} }

// Defaults returns example tiers.
func Defaults() []Policy {
	return []Policy{
		{Name: "gold", Frequency: D(time.Hour), Retention: D(30 * 24 * time.Hour), Lock: D(7 * 24 * time.Hour)},
		{Name: "silver", Frequency: D(6 * time.Hour), Retention: D(14 * 24 * time.Hour), Lock: D(3 * 24 * time.Hour)},
	}
}
