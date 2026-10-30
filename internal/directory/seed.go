package directory

import (
	"fmt"
	"sort"
	"strings"
)

type person struct {
	first, last, dept, title string
	enabled                  bool
}

// Sample org used by `serve` on first start and by the demo.
var people = []person{
	{"Anil", "Mehta", "it", "Systems Administrator", true},
	{"Rosa", "Delgado", "it", "IT Manager", true},
	{"Kwame", "Asante", "it", "Backup Engineer", true},
	{"Hannah", "Lindqvist", "it", "Helpdesk Technician", true},
	{"Jun", "Takahashi", "engineering", "Software Engineer", true},
	{"Marta", "Kowalczyk", "finance", "Accountant", true},
	{"Grace", "Obi", "hr", "HR Generalist", true},
	{"Liam", "Byrne", "sales", "Account Executive", true},
	{"Sofia", "Romano", "engineering", "Senior Software Engineer", true},
	{"Daniel", "Cohen", "sales", "Sales Manager", true},
	{"Meera", "Iyer", "engineering", "QA Engineer", true},
	{"Tobias", "Weber", "finance", "Financial Analyst", true},
	{"Aisha", "Rahman", "sales", "Account Executive", true},
	{"Connor", "Walsh", "engineering", "DevOps Engineer", true},
	{"Yuki", "Mori", "engineering", "Software Engineer", true},
	{"Fernando", "Alves", "sales", "Sales Development Rep", true},
	{"Leah", "Goldberg", "hr", "Recruiter", true},
	{"Oluwaseun", "Adeyemi", "engineering", "Engineering Manager", true},
	{"Camille", "Laurent", "finance", "Controller", true},
	{"Ravi", "Shankar", "engineering", "Software Engineer", true},
	{"Emily", "Hart", "sales", "Account Executive", true},
	{"Mateo", "Fernandez", "engineering", "Data Engineer", true},
	{"Ingrid", "Nilsen", "finance", "Payroll Specialist", true},
	{"Samuel", "Osei", "sales", "Solutions Engineer", true},
	{"Chloe", "Martin", "hr", "HR Director", true},
	{"Nikhil", "Rao", "engineering", "Site Reliability Engineer", true},
	{"Olivia", "Brennan", "sales", "Customer Success Manager", true},
	{"Henrik", "Johansson", "engineering", "Software Engineer", true},
	{"Zainab", "Bello", "finance", "Accounts Payable Clerk", true},
	{"Patrick", "Doyle", "sales", "Account Executive", true},
	{"Mei", "Chen", "engineering", "Staff Engineer", true},
	{"Lucas", "Moreau", "engineering", "Software Engineer", true},
	{"Priyanka", "Desai", "sales", "Sales Operations Analyst", true},
	{"Gabriel", "Santos", "engineering", "Security Engineer", true},
	{"Nora", "Fitzgerald", "hr", "Benefits Coordinator", true},
	{"Arjun", "Kapoor", "engineering", "Software Engineer", true},
	{"Elena", "Petrova", "finance", "Treasury Analyst", true},
	{"Marcus", "Reid", "sales", "Regional Sales Director", true},
	{"Ji-woo", "Park", "engineering", "Mobile Engineer", true},
	{"Thomas", "Keller", "it", "Network Engineer", true},
	{"Fatima", "Zahra", "sales", "Account Executive", false}, // left last month, account kept for audit
	{"Owen", "Price", "engineering", "Software Engineer", true},
	{"Isabel", "Cruz", "finance", "FP&A Manager", true},
	{"Kenji", "Watanabe", "engineering", "Platform Engineer", true},
	{"Amara", "Nwosu", "sales", "Partner Manager", true},
	{"Viktor", "Horvath", "engineering", "Software Engineer", true},
	{"Ruth", "Abebe", "hr", "People Partner", true},
	{"Dylan", "Murphy", "sales", "Account Executive", true},
	{"Sana", "Qureshi", "engineering", "Machine Learning Engineer", true},
	{"Pedro", "Oliveira", "engineering", "Software Engineer", true},
	{"Lena", "Vogel", "finance", "Tax Specialist", true},
	{"Ethan", "Clarke", "sales", "Sales Engineer", false}, // on leave
	{"Ama", "Mensah", "engineering", "Engineering Intern", true},
	{"Rohan", "Malhotra", "it", "Identity Engineer", true},
	{"Julia", "Novak", "engineering", "Software Engineer", true},
	{"Ahmed", "Hassan", "sales", "Account Executive", true},
	{"Clara", "Schmidt", "engineering", "Technical Writer", true},
	{"Tariq", "Aziz", "finance", "Internal Auditor", true},
}

// Seed returns the sample directory: 58 people, 2 service accounts, 8 groups.
func Seed() State {
	s := NewState()
	groups := map[string]*Group{
		"g-it":            {ID: "g-it", Name: "SG-IT", Description: "IT department"},
		"g-engineering":   {ID: "g-engineering", Name: "SG-Engineering", Description: "Engineering department"},
		"g-sales":         {ID: "g-sales", Name: "SG-Sales", Description: "Sales department"},
		"g-finance":       {ID: "g-finance", Name: "SG-Finance", Description: "Finance department"},
		"g-hr":            {ID: "g-hr", Name: "SG-HR", Description: "Human resources"},
		"g-vpn":           {ID: "g-vpn", Name: "VPN-Users", Description: "Allowed to connect to the corporate VPN"},
		"g-domain-admins": {ID: "g-domain-admins", Name: "Domain Admins", Description: "Full control of the domain", Privileged: true},
		"g-backup-ops":    {ID: "g-backup-ops", Name: "Backup Operators", Description: "Can read all files for backup", Privileged: true},
	}
	for i, p := range people {
		id := fmt.Sprintf("u-%03d", i+1)
		sam := strings.ToLower(p.first[:1] + strings.ReplaceAll(p.last, " ", ""))
		s.Users[id] = User{
			ID: id, Username: sam, DisplayName: p.first + " " + p.last,
			Email: strings.ToLower(p.first+"."+p.last) + "@harbourline.local", Enabled: p.enabled,
			Attributes: map[string]string{"department": p.dept, "title": p.title},
		}
		groups["g-"+p.dept].Members = append(groups["g-"+p.dept].Members, id)
		if p.dept == "sales" || p.dept == "it" || p.dept == "engineering" && i%2 == 0 {
			groups["g-vpn"].Members = append(groups["g-vpn"].Members, id)
		}
	}
	for _, svc := range []struct{ id, name, desc string }{
		{"u-059", "svc-sqlbackup", "SQL Server backup agent"},
		{"u-060", "svc-print", "Print server"},
	} {
		s.Users[svc.id] = User{ID: svc.id, Username: svc.name, DisplayName: svc.desc, Enabled: true,
			Attributes: map[string]string{"department": "it", "title": "Service account"}}
	}
	groups["g-domain-admins"].Members = []string{"u-001", "u-002"}
	groups["g-backup-ops"].Members = []string{"u-003", "u-059"}
	for id, g := range groups {
		sort.Strings(g.Members)
		s.Groups[id] = *g
	}
	return s
}
