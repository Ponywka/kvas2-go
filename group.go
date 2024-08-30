package main

import (
	"errors"
	"fmt"
	"github.com/nadoo/ipset"
	"strconv"

	"kvas2-go/models"
	"kvas2-go/pkg/ip-helper"
)

type GroupOptions struct {
	Enabled bool
	FWMark  uint32
	Table   uint16
}

type Group struct {
	*models.Group
	ipsetName string
	options   GroupOptions
}

func (g *Group) Enable() error {
	if g.options.Enabled {
		return nil
	}

	fwmark, err := ipHelper.GetUnusedFwMark(1)
	if err != nil {
		return fmt.Errorf("error while getting free fwmark: %w", err)
	}

	table, err := ipHelper.GetUnusedTable(1)
	if err != nil {
		return fmt.Errorf("error while getting free table: %w", err)
	}

	fwmarkStr := strconv.Itoa(int(fwmark))
	tableStr := strconv.Itoa(int(table))
	out, err := ipHelper.ExecIp("rule", "add", "fwmark", fwmarkStr, "table", tableStr)
	if err != nil {
		return err
	}
	if len(out) != 0 {
		return errors.New(string(out))
	}

	err = ipset.Destroy(g.ipsetName)
	if err != nil {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	err = ipset.Create(g.ipsetName)
	if err != nil {
		return fmt.Errorf("failed to create ipset: %w", err)
	}

	g.options.Enabled = true
	g.options.FWMark = fwmark
	g.options.Table = table

	return nil
}

func (g *Group) Disable() error {
	if !g.options.Enabled {
		return nil
	}

	fwmarkStr := strconv.Itoa(int(g.options.FWMark))
	tableStr := strconv.Itoa(int(g.options.Table))
	out, err := ipHelper.ExecIp("rule", "del", "fwmark", fwmarkStr, "table", tableStr)
	if err != nil {
		return err
	}
	if len(out) != 0 {
		return errors.New(string(out))
	}

	err = ipset.Destroy(g.ipsetName)
	if err != nil {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}

	g.options.Enabled = false
	g.options.FWMark = 0
	g.options.Table = 0

	return nil
}
