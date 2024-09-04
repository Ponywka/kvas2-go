package main

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"strconv"
	"time"

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

func (g *Group) HandleIPv4(names []string, address net.IP, ttl time.Duration) error {
	if !g.options.Enabled {
		return nil
	}

	ttlSeconds := uint32(ttl.Seconds())

DomainSearch:
	for _, domain := range g.Domains {
		if !domain.IsEnabled() {
			continue
		}
		for _, name := range names {
			if domain.IsMatch(name) {
				err := netlink.IpsetAdd(g.ipsetName, &netlink.IPSetEntry{
					IP:      address,
					Timeout: &ttlSeconds,
					Replace: true,
				})
				if err != nil {
					return fmt.Errorf("failed to assign address %s with %s ipset: %w", address, g.ipsetName, err)
				}
				break DomainSearch
			}
		}
	}

	return nil
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

	defaultTimeout := uint32(300)
	err = netlink.IpsetDestroy(g.ipsetName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	err = netlink.IpsetCreate(g.ipsetName, "hash:ip", netlink.IpsetCreateOptions{
		Timeout: &defaultTimeout,
	})
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

	err = netlink.IpsetDestroy(g.ipsetName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}

	g.options.Enabled = false
	g.options.FWMark = 0
	g.options.Table = 0

	return nil
}
