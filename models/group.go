package models

type Group struct {
	ID        int
	Name      string
	Interface string
	Domains   []*Domain
}
