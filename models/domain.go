package models

import (
	"regexp"

	"github.com/IGLOU-EU/go-wildcard/v2"
)

type Domain struct {
	ID      int
	Group   *Group
	Type    string
	Domain  string
	Enable  bool
	Comment string
}

func (d *Domain) IsEnabled() bool {
	return d.Enable
}

func (d *Domain) IsMatch(domainName string) bool {
	switch d.Type {
	case "wildcard":
		return wildcard.Match(d.Domain, domainName)
	case "regex":
		ok, _ := regexp.MatchString(d.Domain, domainName)
		return ok
	case "plaintext":
		return domainName == d.Domain
	}
	return false
}
