package main

import "kvas2-go/models"

type Group struct {
	*models.Group
	FWMark uint32
	Table  uint16
}
