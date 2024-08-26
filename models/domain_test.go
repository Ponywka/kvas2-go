package models

import "testing"

func TestDomain_IsMatch_Plaintext(t *testing.T) {
	domain := &Domain{
		Type:   "plaintext",
		Domain: "example.com",
	}
	if !domain.IsMatch("example.com") {
		t.Fatal("&Domain{Type: \"plaintext\", Domain: \"example.com\"}.IsMatch(\"example.com\") returns false")
	}
	if domain.IsMatch("noexample.com") {
		t.Fatal("&Domain{Type: \"plaintext\", Domain: \"example.com\"}.IsMatch(\"noexample.com\") returns true")
	}
}

func TestDomain_IsMatch_Wildcard(t *testing.T) {
	domain := &Domain{
		Type:   "wildcard",
		Domain: "ex*le.com",
	}
	if !domain.IsMatch("example.com") {
		t.Fatal("&Domain{Type: \"wildcard\", Domain: \"ex*le.com\"}.IsMatch(\"example.com\") returns false")
	}
	if domain.IsMatch("noexample.com") {
		t.Fatal("&Domain{Type: \"wildcard\", Domain: \"ex*le.com\"}.IsMatch(\"noexample.com\") returns true")
	}
}

func TestDomain_IsMatch_RegEx(t *testing.T) {
	domain := &Domain{
		Type:   "regex",
		Domain: "^ex[apm]{3}le.com$",
	}
	if !domain.IsMatch("example.com") {
		t.Fatal("&Domain{Type: \"regex\", Domain: \"^ex[apm]{3}le.com$\"}.IsMatch(\"example.com\") returns false")
	}
	if domain.IsMatch("noexample.com") {
		t.Fatal("&Domain{Type: \"regex\", Domain: \"^ex[apm]{3}le.com$\"}.IsMatch(\"noexample.com\") returns true")
	}
}
