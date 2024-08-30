package main

import "kvas2-go/models"

type GroupOptions struct {
	Enabled bool
	FWMark  uint32
	Table   uint16
}

type Group struct {
	*models.Group
	options GroupOptions
}
