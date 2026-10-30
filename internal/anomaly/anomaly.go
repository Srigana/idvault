// Package anomaly flags suspicious changes between two snapshots.
//
// The thresholds are fixed. A real deployment would want a baseline per
// tenant (normal churn on a Monday is not normal churn at 3am on a Sunday).
package anomaly

import (
	"fmt"

	"idvault/internal/directory"
)

type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Targets  []string `json:"targets,omitempty"`
}

type Detector struct {
	// Both must be met, so deleting 3 of 4 test users isn't flagged but
	// deleting 25 of 60 is.
	Ratio    float64
	MinCount int
}

func DefaultDetector() Detector { return Detector{Ratio: 0.2, MinCount: 5} }

func (d Detector) Analyze(prev, cur directory.State, ch directory.Changes) []Finding {
	var out []Finding
	if d.wave(len(ch.UsersDeleted), len(prev.Users)) {
		out = append(out, Finding{"mass_user_deletion", Critical,
			fmt.Sprintf("%d of %d users deleted in one interval", len(ch.UsersDeleted), len(prev.Users)), ch.UsersDeleted})
	}
	if d.wave(len(ch.UsersDisabled), len(prev.Users)) {
		out = append(out, Finding{"mass_user_disable", High,
			fmt.Sprintf("%d of %d users disabled in one interval", len(ch.UsersDisabled), len(prev.Users)), ch.UsersDisabled})
	}
	if len(ch.GroupsDeleted) >= 2 && float64(len(ch.GroupsDeleted)) >= d.Ratio*float64(len(prev.Groups)) {
		out = append(out, Finding{"mass_group_deletion", Critical,
			fmt.Sprintf("%d of %d groups deleted", len(ch.GroupsDeleted), len(prev.Groups)), ch.GroupsDeleted})
	}
	for _, m := range ch.MembershipAdded {
		if g, ok := cur.Groups[m.GroupID]; ok && g.Privileged {
			name := m.UserID
			if u, ok := cur.Users[m.UserID]; ok {
				name = u.Username
			}
			out = append(out, Finding{"privileged_membership_added", High,
				fmt.Sprintf("%s added to privileged group %q", name, g.Name), []string{m.GroupID, m.UserID}})
		}
	}
	for _, id := range ch.GroupsAdded {
		if cur.Groups[id].Privileged {
			out = append(out, Finding{"privileged_group_created", Medium,
				fmt.Sprintf("new privileged group %q", cur.Groups[id].Name), []string{id}})
		}
	}
	for _, id := range ch.GroupsDeleted {
		if prev.Groups[id].Privileged {
			out = append(out, Finding{"privileged_group_deleted", High,
				fmt.Sprintf("privileged group %q deleted", prev.Groups[id].Name), []string{id}})
		}
	}
	return out
}

func (d Detector) wave(changed, population int) bool {
	return population > 0 && changed >= d.MinCount && float64(changed) >= d.Ratio*float64(population)
}

// Suspicious reports whether any finding is high or critical.
func Suspicious(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == High || f.Severity == Critical {
			return true
		}
	}
	return false
}
