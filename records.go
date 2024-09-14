package main

import (
	"bytes"
	"net"
	"sync"
	"time"
)

type ARecord struct {
	Address  net.IP
	Deadline time.Time
}

func NewARecord(addr net.IP, deadline time.Time) *ARecord {
	return &ARecord{
		Address:  addr,
		Deadline: deadline,
	}
}

type CNameRecord struct {
	Alias    string
	Deadline time.Time
}

func NewCNameRecord(domainName string, deadline time.Time) *CNameRecord {
	return &CNameRecord{
		Alias:    domainName,
		Deadline: deadline,
	}
}

type Records struct {
	mutex        sync.RWMutex
	ARecords     map[string][]*ARecord
	CNameRecords map[string]*CNameRecord
}

func (r *Records) cleanupARecords(now time.Time) {
	for name, aRecords := range r.ARecords {
		i := 0
		for _, aRecord := range aRecords {
			if now.After(aRecord.Deadline) {
				continue
			}
			aRecords[i] = aRecord
			i++
		}
		aRecords = aRecords[:i]
		if i == 0 {
			delete(r.ARecords, name)
		}
	}
}

func (r *Records) cleanupCNameRecords(now time.Time) {
	for name, record := range r.CNameRecords {
		if now.After(record.Deadline) {
			delete(r.CNameRecords, name)
		}
	}
}

func (r *Records) getAliasedDomain(now time.Time, domainName string) string {
	processedDomains := make(map[string]struct{})
	for {
		if _, processed := processedDomains[domainName]; processed {
			// Loop detected!
			return ""
		} else {
			processedDomains[domainName] = struct{}{}
		}

		cname, ok := r.CNameRecords[domainName]
		if !ok {
			break
		}
		if now.After(cname.Deadline) {
			delete(r.CNameRecords, domainName)
			break
		}
		domainName = cname.Alias
	}
	return domainName
}

func (r *Records) getActualARecords(now time.Time, domainName string) []*ARecord {
	aRecords, ok := r.ARecords[domainName]
	if !ok {
		return nil
	}

	i := 0
	for _, aRecord := range aRecords {
		if now.After(aRecord.Deadline) {
			continue
		}
		aRecords[i] = aRecord
		i++
	}
	aRecords = aRecords[:i]
	if i == 0 {
		delete(r.ARecords, domainName)
		return nil
	}

	return aRecords
}

func (r *Records) getActualCNames(now time.Time, domainName string, fromEnd bool) []string {
	processedDomains := make(map[string]struct{})
	cNameList := make([]string, 0)
	if fromEnd {
		domainName = r.getAliasedDomain(now, domainName)
		cNameList = append(cNameList, domainName)
	}
	r.cleanupCNameRecords(now)
	for {
		if _, processed := processedDomains[domainName]; processed {
			// Loop detected!
			return nil
		} else {
			processedDomains[domainName] = struct{}{}
		}

		found := false
		for aliasFrom, aliasTo := range r.CNameRecords {
			if aliasTo.Alias == domainName {
				cNameList = append(cNameList, aliasFrom)
				domainName = aliasFrom
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return cNameList
}

func (r *Records) Cleanup() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()
	r.cleanupARecords(now)
	r.cleanupCNameRecords(now)
}

func (r *Records) GetCNameRecords(domainName string, fromEnd bool) []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	now := time.Now()

	return r.getActualCNames(now, domainName, fromEnd)
}

func (r *Records) GetARecords(domainName string) []*ARecord {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()

	return r.getActualARecords(now, r.getAliasedDomain(now, domainName))
}

func (r *Records) AddCNameRecord(domainName string, cName string, ttl time.Duration) {
	if domainName == cName {
		// Can't assing to yourself
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()

	delete(r.ARecords, domainName)
	r.CNameRecords[domainName] = NewCNameRecord(cName, now.Add(ttl))
}

func (r *Records) AddARecord(domainName string, addr net.IP, ttl time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()

	delete(r.CNameRecords, domainName)
	if _, ok := r.ARecords[domainName]; !ok {
		r.ARecords[domainName] = make([]*ARecord, 0)
	}
	for _, aRecord := range r.ARecords[domainName] {
		if bytes.Compare(aRecord.Address, addr) == 0 {
			aRecord.Deadline = now.Add(ttl)
			return
		}
	}
	r.ARecords[domainName] = append(r.ARecords[domainName], NewARecord(addr, now.Add(ttl)))
}

func (r *Records) ListKnownDomains() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()
	r.cleanupARecords(now)
	r.cleanupCNameRecords(now)

	domains := map[string]struct{}{}
	for name, _ := range r.ARecords {
		domains[name] = struct{}{}
	}
	for name, _ := range r.CNameRecords {
		domains[name] = struct{}{}
	}

	domainsList := make([]string, len(domains))
	i := 0
	for name, _ := range domains {
		domainsList[i] = name
		i++
	}
	return domainsList
}

func NewRecords() *Records {
	return &Records{
		ARecords:     make(map[string][]*ARecord),
		CNameRecords: make(map[string]*CNameRecord),
	}
}
