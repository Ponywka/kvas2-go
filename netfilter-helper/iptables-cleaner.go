package netfilterHelper

import (
	"fmt"
	"strings"
)

func (nh *NetfilterHelper) ClearIPTables(chainPrefix string) error {
	jumpToChainPrefix := fmt.Sprintf("-j %s", chainPrefix)
	tableList := []string{"nat", "mangle", "filter"}

	for _, table := range tableList {
		chainListToDelete := make([]string, 0)

		chains, err := nh.IPTables.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing chains error: %w", err)
		}

		for _, chain := range chains {
			if strings.HasPrefix(chain, chainPrefix) {
				chainListToDelete = append(chainListToDelete, chain)
				continue
			}

			rules, err := nh.IPTables.List(table, chain)
			if err != nil {
				return fmt.Errorf("listing rules error: %w", err)
			}

			for _, rule := range rules {
				ruleSlice := strings.Split(rule, " ")
				if len(ruleSlice) < 2 || ruleSlice[0] != "-A" || ruleSlice[1] != chain {
					// TODO: Warn
					continue
				}
				ruleSlice = ruleSlice[2:]

				if strings.Contains(strings.Join(ruleSlice, " "), jumpToChainPrefix) {
					err := nh.IPTables.Delete(table, chain, ruleSlice...)
					if err != nil {
						return fmt.Errorf("rule deletion error: %w", err)
					}
				}
			}
		}

		for _, chain := range chainListToDelete {
			err := nh.IPTables.ClearAndDeleteChain(table, chain)
			if err != nil {
				return fmt.Errorf("deleting chain error: %w", err)
			}
		}
	}

	return nil
}
