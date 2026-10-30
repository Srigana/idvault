package directory

import (
	"reflect"
	"sort"
)

type Membership struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

type Changes struct {
	UsersAdded        []string     `json:"users_added"`
	UsersDeleted      []string     `json:"users_deleted"`
	UsersModified     []string     `json:"users_modified"`
	UsersDisabled     []string     `json:"users_disabled"`
	GroupsAdded       []string     `json:"groups_added"`
	GroupsDeleted     []string     `json:"groups_deleted"`
	GroupsModified    []string     `json:"groups_modified"`
	MembershipAdded   []Membership `json:"membership_added"`
	MembershipRemoved []Membership `json:"membership_removed"`
}

func (c Changes) Empty() bool {
	return len(c.UsersAdded)+len(c.UsersDeleted)+len(c.UsersModified)+
		len(c.GroupsAdded)+len(c.GroupsDeleted)+len(c.GroupsModified)+
		len(c.MembershipAdded)+len(c.MembershipRemoved) == 0
}

// Diff returns what changed going from a to b. All slices are sorted.
func Diff(a, b State) Changes {
	var c Changes
	for _, id := range SortedKeys(b.Users) {
		bu := b.Users[id]
		au, ok := a.Users[id]
		switch {
		case !ok:
			c.UsersAdded = append(c.UsersAdded, id)
		case !reflect.DeepEqual(normUser(au), normUser(bu)):
			c.UsersModified = append(c.UsersModified, id)
			if au.Enabled && !bu.Enabled {
				c.UsersDisabled = append(c.UsersDisabled, id)
			}
		}
	}
	for _, id := range SortedKeys(a.Users) {
		if _, ok := b.Users[id]; !ok {
			c.UsersDeleted = append(c.UsersDeleted, id)
		}
	}
	for _, id := range SortedKeys(b.Groups) {
		bg := b.Groups[id]
		ag, ok := a.Groups[id]
		if !ok {
			c.GroupsAdded = append(c.GroupsAdded, id)
			for _, m := range bg.Members {
				c.MembershipAdded = append(c.MembershipAdded, Membership{id, m})
			}
			continue
		}
		if !ag.SameMeta(bg) {
			c.GroupsModified = append(c.GroupsModified, id)
		}
		as, bs := toSet(ag.Members), toSet(bg.Members)
		for _, m := range bg.Members {
			if !as[m] {
				c.MembershipAdded = append(c.MembershipAdded, Membership{id, m})
			}
		}
		for _, m := range ag.Members {
			if !bs[m] {
				c.MembershipRemoved = append(c.MembershipRemoved, Membership{id, m})
			}
		}
	}
	for _, id := range SortedKeys(a.Groups) {
		if _, ok := b.Groups[id]; !ok {
			c.GroupsDeleted = append(c.GroupsDeleted, id)
			for _, m := range a.Groups[id].Members {
				c.MembershipRemoved = append(c.MembershipRemoved, Membership{id, m})
			}
		}
	}
	sortMs(c.MembershipAdded)
	sortMs(c.MembershipRemoved)
	return c
}

func normUser(u User) User {
	if len(u.Attributes) == 0 {
		u.Attributes = nil
	}
	return u
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sortMs(ms []Membership) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].GroupID != ms[j].GroupID {
			return ms[i].GroupID < ms[j].GroupID
		}
		return ms[i].UserID < ms[j].UserID
	})
}
