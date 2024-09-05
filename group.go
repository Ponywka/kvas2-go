package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"kvas2-go/models"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
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

func (g *Group) Enable(a *App) error {
	if g.options.Enabled {
		return nil
	}

	var err error

	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{
		0:   {},
		253: {},
		254: {},
		255: {},
	}
	var table int
	var mark uint32

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for {
		if _, exists := tableMap[table]; exists {
			table++
			continue
		}
		break
	}

	for {
		if _, exists := markMap[mark]; exists {
			mark++
			continue
		}
		break
	}

	rule := netlink.NewRule()
	rule.Mark = mark
	rule.Table = table
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

	preroutingChainName := fmt.Sprintf("%sROUTING_%d_PREROUTING", a.Config.ChainPostfix, g.ID)

	err = a.IPTables.ClearChain("mangle", preroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = a.IPTables.AppendUnique("mangle", preroutingChainName, "-m", "set", "--match-set", g.ipsetName, "dst", "-j", "MARK", "--set-mark", strconv.Itoa(int(mark)))
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	err = a.IPTables.AppendUnique("mangle", "PREROUTING", "-j", preroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to linking chain: %w", err)
	}

	postroutingChainName := fmt.Sprintf("%sROUTING_%d_POSTROUTING", a.Config.ChainPostfix, g.ID)

	err = a.IPTables.ClearChain("nat", postroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = a.IPTables.AppendUnique("nat", postroutingChainName, "-o", g.Interface, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	err = a.IPTables.AppendUnique("nat", "POSTROUTING", "-j", postroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to linking chain: %w", err)
	}

	g.options.Enabled = true

	return nil
}

func (g *Group) Disable(a *App) error {
	if !g.options.Enabled {
		return nil
	}

	var err error

	preroutingChainName := fmt.Sprintf("%sROUTING_%d_PREROUTING", a.Config.ChainPostfix, g.ID)

	err = a.IPTables.DeleteIfExists("mangle", "PREROUTING", "-j", preroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to unlinking chain: %w", err)
	}

	err = a.IPTables.ClearAndDeleteChain("mangle", preroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to delete chain: %w", err)
	}

	postroutingChainName := fmt.Sprintf("%sROUTING_%d_POSTROUTING", a.Config.ChainPostfix, g.ID)

	err = a.IPTables.DeleteIfExists("nat", "POSTROUTING", "-j", postroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to unlinking chain: %w", err)
	}

	err = a.IPTables.ClearAndDeleteChain("nat", postroutingChainName)
	if err != nil {
		return fmt.Errorf("failed to delete chain: %w", err)
	}

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
