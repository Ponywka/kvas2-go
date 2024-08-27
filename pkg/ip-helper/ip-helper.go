package ipHelper

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
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

	out, err := ExecIp("rule", "show")
	if err != nil {
		return nil, fmt.Errorf("error while getting rules: %w", err)
	}

	re := regexp.MustCompile(`fwmark\s+0x([0-9a-fA-F]+)`)
	for _, line := range strings.Split(string(out), "\n") {
		match := re.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}

		hexStr := match[1]
		hexValue, err := strconv.ParseInt(hexStr, 16, 64)
		if err == nil {
			markMap[uint32(hexValue)] = struct{}{}
		}
	}

	marks := make([]uint32, len(markMap))
	counter := 0
	for mark, _ := range markMap {
		marks[counter] = mark
		counter++
	}

	return marks, nil
}

func GetUnusedFwMark() (uint32, error) {
	usedFwMarks, err := GetUsedFwMarks()
	if err != nil {
		return 0, fmt.Errorf("error while getting used fwmarks: %w", err)
	}

	fwmark := uint32(1)
	for slices.Contains(usedFwMarks, fwmark) {
		fwmark++
		if fwmark == 0xFFFFFFFF {
			return 0, ErrMaxFwMarkSize
		}
	}
	return fwmark, nil
}

func GetTableAliases() (map[string]uint16, error) {
	tables := map[string]uint16{
		"unspec":  0,
		"default": 253,
		"main":    254,
		"local":   255,
	}

	file, err := os.Open("/opt/etc/iproute2/rt_tables")
	if err != nil {
		if os.IsNotExist(err) {
			return tables, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || len(strings.TrimSpace(line)) == 0 {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			tableID, err := strconv.Atoi(parts[0])
			if err == nil {
				tables[parts[1]] = uint16(tableID)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tables, nil
}

func GetUsedTables() ([]uint16, error) {
	tableMap := map[uint16]struct{}{
		0:   {},
		253: {},
		254: {},
		255: {},
	}

	tableAliases, err := GetTableAliases()
	if err != nil {
		return nil, fmt.Errorf("error while getting table aliases: %w", err)
	}

	out, err := ExecIp("route", "show", "table", "all")
	if err != nil {
		return nil, fmt.Errorf("error while getting routes: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "table") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "table" && i+1 < len(parts) {
					tableNum, ok := tableAliases[parts[i+1]]
					if !ok {
						tableNumInt, _ := strconv.Atoi(parts[i+1])
						tableNum = uint16(tableNumInt)
					}
					tableMap[tableNum] = struct{}{}
				}
			}
		}
	}

	out, err = ExecIp("rule", "show")
	if err != nil {
		return nil, fmt.Errorf("error while getting rules: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "lookup") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "lookup" && i+1 < len(parts) {
					tableNum, ok := tableAliases[parts[i+1]]
					if !ok {
						tableNumInt, _ := strconv.Atoi(parts[i+1])
						tableNum = uint16(tableNumInt)
					}
					tableMap[tableNum] = struct{}{}
				}
			}
		}
	}

	tables := make([]uint16, len(tableMap))
	counter := 0
	for table, _ := range tableMap {
		tables[counter] = table
		counter++
	}

	return tables, nil
}

func GetUnusedTable() (uint16, error) {
	usedTables, err := GetUsedTables()
	if err != nil {
		return 0, fmt.Errorf("error while getting used tables: %w", err)
	}

	tableID := uint16(1)
	for slices.Contains(usedTables, tableID) {
		tableID++
		if tableID > 0x3FF {
			return 0, ErrMaxTableSize
		}
	}
	return tableID, nil
}
