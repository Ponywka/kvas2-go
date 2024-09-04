package ipHelper

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"slices"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var (
	ErrMaxTableSize  = errors.New("max table size")
	ErrMaxFwMarkSize = errors.New("max fwmark size")
)

func ExecIp(args ...string) ([]byte, error) {
	cmd := exec.Command("ip", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func GetUsedFwMarks() ([]uint32, error) {
	markMap := make(map[uint32]struct{})

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("error while getting rules: %w", err)
	}

	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
	}

	marks := make([]uint32, len(markMap))
	counter := 0
	for mark, _ := range markMap {
		marks[counter] = mark
		counter++
	}

	return marks, nil
}

func GetUnusedFwMark(startFrom uint32) (uint32, error) {
	usedFwMarks, err := GetUsedFwMarks()
	if err != nil {
		return 0, fmt.Errorf("error while getting used fwmarks: %w", err)
	}

	fwmark := startFrom
	for slices.Contains(usedFwMarks, fwmark) {
		fwmark++
		if fwmark == 0xFFFFFFFF {
			return 0, ErrMaxFwMarkSize
		}
	}
	return fwmark, nil
}

func GetUsedTables() ([]int, error) {
	tableMap := map[int]struct{}{
		0:   {},
		253: {},
		254: {},
		255: {},
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("error while getting routes: %w", err)
	}

	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("error while getting rules: %w", err)
	}

	for _, rule := range rules {
		tableMap[rule.Table] = struct{}{}
	}

	tables := make([]int, len(tableMap))
	counter := 0
	for table, _ := range tableMap {
		tables[counter] = table
		counter++
	}

	return tables, nil
}

func GetUnusedTable(startFrom int) (int, error) {
	usedTables, err := GetUsedTables()
	if err != nil {
		return 0, fmt.Errorf("error while getting used tables: %w", err)
	}

	tableID := startFrom
	for slices.Contains(usedTables, tableID) {
		tableID++
		if tableID > 0x3FF {
			return 0, ErrMaxTableSize
		}
	}
	return tableID, nil
}
