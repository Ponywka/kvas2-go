package models

type Domain struct {
	ID      int
	Group   *Group
	Type    string
	Domain  string
	Enable  bool
	Comment string
}
