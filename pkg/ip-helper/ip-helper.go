package ipHelper

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func execIp(args ...string) ([]byte, error) {
	cmd := exec.Command("ip", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func GetUsedFwMarks() ([]int, error) {
	markMap := make(map[int]struct{})

	out, err := execIp("rule", "show")
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
			markMap[int(hexValue)] = struct{}{}
		}
	}

	marks := make([]int, len(markMap))
	counter := 0
	for mark, _ := range markMap {
		marks[counter] = mark
		counter++
	}

	return marks, nil
}

func GetTableAliases() (map[string]int, error) {
	tables := map[string]int{
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
				tables[parts[1]] = tableID
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tables, nil
}

func GetUsedTables() ([]int, error) {
	tableMap := map[int]struct{}{
		0:   {},
		253: {},
		254: {},
		255: {},
	}

	tableAliases, err := GetTableAliases()
	if err != nil {
		return nil, fmt.Errorf("error while getting table aliases: %w", err)
	}

	out, err := execIp("route", "show", "table", "all")
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
						tableNum, _ = strconv.Atoi(parts[i+1])
					}
					tableMap[tableNum] = struct{}{}
				}
			}
		}
	}

	tables := make([]int, len(tableMap))
	counter := 0
	for table, _ := range tableMap {
		tables[counter] = table
		counter++
	}

	return tables, nil
}
