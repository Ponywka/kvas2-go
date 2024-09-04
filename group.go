package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"kvas2-go/models"
	"kvas2-go/pkg/ip-helper"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

type GroupOptions struct {
	Enabled bool
	ipRule  *netlink.Rule
	ipRoute *netlink.Route
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
					return fmt.Errorf("failed to assign address: %w", err)
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

	var err error

	rule := netlink.NewRule()
	rule.Mark, err = ipHelper.GetUnusedFwMark(1)
	if err != nil {
		return fmt.Errorf("error while getting free fwmark: %w", err)
	}
	rule.Table, err = ipHelper.GetUnusedTable(1)
	if err != nil {
		return fmt.Errorf("error while getting free table: %w", err)
	}
	err = netlink.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("error while adding rule: %w", err)
	}
	g.options.ipRule = rule

	iface, err := netlink.LinkByName(g.Interface)
	if err != nil {
		log.Warn().Str("interface", g.Interface).Msg("error while getting interface")
	}

	if iface != nil {
		route := &netlink.Route{
			LinkIndex: iface.Attrs().Index,
			Table:     rule.Table,
			Dst: &net.IPNet{
				IP:   []byte{0, 0, 0, 0},
				Mask: []byte{0, 0, 0, 0},
			},
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("error while adding route: %w", err)
		}
		g.options.ipRoute = route
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

	return nil
}

func (g *Group) Disable() error {
	if !g.options.Enabled {
		return nil
	}

	var err error

	if g.options.ipRule != nil {
		err = netlink.RuleDel(g.options.ipRule)
		if err != nil {
			return fmt.Errorf("error while deleting rule: %w", err)
		}
		g.options.ipRule = nil
	}

	if g.options.ipRoute != nil {
		err = netlink.RouteDel(g.options.ipRoute)
		if err != nil {
			return fmt.Errorf("error while deleting route: %w", err)
		}
		g.options.ipRule = nil
	}

	err = netlink.IpsetDestroy(g.ipsetName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}

	g.options.Enabled = false

	return nil
}
