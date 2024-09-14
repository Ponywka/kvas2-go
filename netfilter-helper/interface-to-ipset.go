package netfilterHelper

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"net"
	"strconv"
)

type IfaceToIPSet struct {
	IPTables     *iptables.IPTables
	ChainName    string
	IfaceName    string
	IPSetName    string
	SoftwareMode bool

	Enabled bool

	mark    uint32
	table   int
	ipRule  *netlink.Rule
	ipRoute *netlink.Route
}

func (r *IfaceToIPSet) PutIPTable(table string) error {
	var err error

	if !r.SoftwareMode {
		if table == "all" || table == "mangle" {
			err = r.IPTables.ClearChain("mangle", r.ChainName)
			if err != nil {
				return fmt.Errorf("failed to clear chain: %w", err)
			}

			for _, iptablesArgs := range [][]string{
				// Source: https://github.com/qzeleza/kvas/blob/3fdbbd1ace7b57b11bf88d8db3882d94a1d6e01c/opt/etc/ndm/ndm#L194-L206
				{"-m", "set", "!", "--match-set", r.IPSetName, "dst", "-j", "RETURN"},
				{"-j", "CONNMARK", "--restore-mark"},
				{"-m", "mark", "--mark", strconv.Itoa(int(r.mark)), "-j", "RETURN"},
				// This command not working
				// {"--syn", "-j", "MARK", "--set-mark", strconv.Itoa(int(mark))},
				{"-m", "conntrack", "--ctstate", "NEW", "-j", "MARK", "--set-mark", strconv.Itoa(int(r.mark))},
				{"-j", "CONNMARK", "--save-mark"},
			} {
				err = r.IPTables.AppendUnique("mangle", r.ChainName, iptablesArgs...)
				if err != nil {
					return fmt.Errorf("failed to append rule: %w", err)
				}
			}

			err = r.IPTables.AppendUnique("mangle", "PREROUTING", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
			}

			err = r.IPTables.AppendUnique("mangle", "OUTPUT", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to OUTPUT: %w", err)
			}
		}
	} else {
		if table == "all" || table == "mangle" {
			preroutingChainName := fmt.Sprintf("%s_PRR", r.ChainName)

			err = r.IPTables.ClearChain("mangle", preroutingChainName)
			if err != nil {
				return fmt.Errorf("failed to clear chain: %w", err)
			}

			err = r.IPTables.AppendUnique("mangle", preroutingChainName, "-m", "set", "--match-set", r.IPSetName, "dst", "-j", "MARK", "--set-mark", strconv.Itoa(int(r.mark)))
			if err != nil {
				return fmt.Errorf("failed to create rule: %w", err)
			}

			err = r.IPTables.AppendUnique("mangle", "PREROUTING", "-j", preroutingChainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
			}
		}
	}

	if table == "all" || table == "nat" {
		postroutingChainName := fmt.Sprintf("%s_POR", r.ChainName)

		err = r.IPTables.ClearChain("nat", postroutingChainName)
		if err != nil {
			return fmt.Errorf("failed to clear chain: %w", err)
		}

		err = r.IPTables.AppendUnique("nat", postroutingChainName, "-o", r.IfaceName, "-j", "MASQUERADE")
		if err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		err = r.IPTables.AppendUnique("nat", "POSTROUTING", "-j", postroutingChainName)
		if err != nil {
			return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
		}
	}

	return nil
}

func (r *IfaceToIPSet) IfaceHandle() error {
	// Find interface
	iface, err := netlink.LinkByName(r.IfaceName)
	if err != nil {
		log.Warn().Str("interface", r.IfaceName).Err(err).Msg("error while getting interface")
	}

	// Mapping iface with table
	if iface != nil {
		route := &netlink.Route{
			LinkIndex: iface.Attrs().Index,
			Table:     r.table,
			Dst:       &net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}},
		}
		// Delete rule if exists
		err = netlink.RouteDel(route)
		if err != nil {
			log.Warn().Str("interface", r.IfaceName).Err(err).Msg("error while deleting route")
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("error while mapping iface with table: %w", err)
		}
		r.ipRoute = route
	}

	return nil
}

func (r *IfaceToIPSet) ForceEnable() error {
	// Release used mark and table
	r.Disable()
	r.mark = 0
	r.table = 0

	// Find unused mark and table
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

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
		if _, exists := tableMap[r.table]; exists {
			r.table++
			continue
		}
		break
	}

	for {
		if _, exists := markMap[r.mark]; exists {
			r.mark++
			continue
		}
		break
	}

	// IPTables rules
	err = r.PutIPTable("all")
	if err != nil {
		return nil
	}

	// Mapping mark with table
	rule := netlink.NewRule()
	rule.Mark = r.mark
	rule.Table = r.table
	err = netlink.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("error while mapping mark with table: %w", err)
	}
	r.ipRule = rule

	err = r.IfaceHandle()
	if err != nil {
		return nil
	}

	r.Enabled = true
	return nil
}

func (r *IfaceToIPSet) Disable() []error {
	var errs []error
	var err error

	if !r.SoftwareMode {
		err = r.IPTables.DeleteIfExists("mangle", "PREROUTING", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule from PREROUTING: %w", err))
		}

		err = r.IPTables.DeleteIfExists("mangle", "OUTPUT", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule from OUTPUT: %w", err))
		}

		err = r.IPTables.ClearAndDeleteChain("mangle", r.ChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
		}
	} else {
		preroutingChainName := fmt.Sprintf("%s_PRR", r.ChainName)

		err = r.IPTables.DeleteIfExists("mangle", "PREROUTING", "-j", preroutingChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule from PREROUTING: %w", err))
		}

		err = r.IPTables.ClearAndDeleteChain("mangle", preroutingChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
		}
	}

	postroutingChainName := fmt.Sprintf("%s_POR", r.ChainName)

	err = r.IPTables.DeleteIfExists("nat", "POSTROUTING", "-j", postroutingChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = r.IPTables.ClearAndDeleteChain("nat", postroutingChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	if r.ipRule != nil {
		err = netlink.RuleDel(r.ipRule)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ipRule = nil
	}

	if r.ipRoute != nil {
		err = netlink.RouteDel(r.ipRoute)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ipRule = nil
	}

	r.Enabled = false
	return errs
}

func (r *IfaceToIPSet) Enable() error {
	if r.Enabled {
		return nil
	}

	err := r.ForceEnable()
	if err != nil {
		r.Disable()
		return err
	}

	return nil
}

func (nh *NetfilterHelper) IfaceToIPSet(name string, ifaceName, ipsetName string, softwareMode bool) *IfaceToIPSet {
	return &IfaceToIPSet{
		IPTables:  nh.IPTables,
		ChainName: name,
		IfaceName: ifaceName,
		IPSetName: ipsetName,
	}
}
