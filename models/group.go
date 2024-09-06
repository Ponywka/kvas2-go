package models

type Group struct {
	ID         int
	Name       string
	Interface  string
	FixProtect bool
	Domains    []*Domain
}
