package recoverableIPTables

import (
	"github.com/coreos/go-iptables/iptables"
	"reflect"
)

type IPTablesRule struct {
	Position int
	RuleSpec []string
}

type IPTables struct {
	ipt   *iptables.IPTables
	cache map[string]map[string][]IPTablesRule
}

/*
 * Chain
 */

func (r *IPTables) clearChain(table, chain string) {
	if r.cache[table] == nil {
		r.cache[table] = make(map[string][]IPTablesRule)
	}
	r.cache[table][chain] = nil
}

func (r *IPTables) delChain(table, chain string) {
	if r.cache[table] == nil {
		return
	}
	delete(r.cache[table], chain)
}

/*
 * Rule
 */

func (r *IPTables) delRule(table, chain string, rulespec ...string) {
	if r.cache[table] == nil {
		r.cache[table] = make(map[string][]IPTablesRule)
	}
	for idx, rule := range r.cache[table][chain] {
		if !reflect.DeepEqual(rulespec, rule.RuleSpec) {
			continue
		}
		copy(r.cache[table][chain][idx:], r.cache[table][chain][idx+1:])
		r.cache[table][chain] = r.cache[table][chain][:len(r.cache[table][chain])-1]
		break
	}
}

func (r *IPTables) addRuleUnique(table, chain string, position int, rulespec ...string) {
	if r.cache[table] == nil {
		r.cache[table] = make(map[string][]IPTablesRule)
	}
	for _, rule := range r.cache[table][chain] {
		if reflect.DeepEqual(rulespec, rule.RuleSpec) {
			return
		}
	}
	r.cache[table][chain] = append(r.cache[table][chain], IPTablesRule{
		Position: position,
		RuleSpec: rulespec,
	})
}

/*
 * Mappings
 */

func (r *IPTables) ClearChain(table, chain string) error {
	err := r.ipt.ClearChain(table, chain)
	if err != nil {
		return err
	}
	r.clearChain(table, chain)
	return nil
}

func (r *IPTables) ClearAndDeleteChain(table, chain string) error {
	err := r.ipt.ClearAndDeleteChain(table, chain)
	if err != nil {
		return err
	}
	r.delChain(table, chain)
	return nil
}

func (r *IPTables) AppendUnique(table, chain string, rulespec ...string) error {
	err := r.ipt.AppendUnique(table, chain, rulespec...)
	if err != nil {
		return err
	}
	r.addRuleUnique(table, chain, 0, rulespec...)
	return nil
}

func (r *IPTables) InsertUnique(table, chain string, pos int, rulespec ...string) error {
	err := r.ipt.InsertUnique(table, chain, pos, rulespec...)
	if err != nil {
		return err
	}
	r.addRuleUnique(table, chain, pos, rulespec...)
	return nil
}

func (r *IPTables) DeleteIfExists(table, chain string, rulespec ...string) error {
	err := r.ipt.DeleteIfExists(table, chain, rulespec...)
	if err != nil {
		return err
	}
	r.delRule(table, chain, rulespec...)
	return nil
}

func New() (*IPTables, error) {
	ipt, err := iptables.New()
	return &IPTables{
		ipt:   ipt,
		cache: make(map[string]map[string][]IPTablesRule),
	}, err
}
