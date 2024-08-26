package main

import (
	"net"
	"sync"
	"time"
)

type Records struct {
	mutex        sync.RWMutex
	aRecords     map[string]map[string]time.Time
	cnameRecords map[string]map[string]time.Time
}

func (r *Records) getCNames(domainName string, recursive bool) []string {
	cNameList := make([]string, 0)
	for cname, ttl := range r.cnameRecords[domainName] {
		if time.Now().Sub(ttl).Nanoseconds() > 0 {
			delete(r.cnameRecords[domainName], cname)
			if len(r.cnameRecords[domainName]) == 0 {
				delete(r.cnameRecords, domainName)
				return nil
			}
			continue
		}
		cNameList = append(cNameList, cname)
	}

	if recursive {
		origCNameLen := len(cNameList)
		for i := 0; i < origCNameLen; i++ {
			parentList := r.getCNames(cNameList[i], true)
			if parentList != nil {
				cNameList = append(cNameList, parentList...)
			}
		}
	}

	return cNameList
}

func (r *Records) GetCNameRecords(domainName string, recursive bool) []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.getCNames(domainName, recursive)
}

func (r *Records) GetARecords(domainName string, recursive bool) []net.IP {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	cNameList := []string{domainName}
	if recursive {
		cNameList = append(cNameList, r.getCNames(domainName, true)...)
	}

	aRecords := make([]net.IP, 0)
	for _, cName := range cNameList {
		for addr, ttl := range r.aRecords[cName] {
			if time.Now().Sub(ttl).Nanoseconds() > 0 {
				delete(r.aRecords[cName], addr)
				if len(r.aRecords[cName]) == 0 {
					delete(r.aRecords, cName)
					break
				}
				continue
			}
			aRecords = append(aRecords, []byte(addr))
		}
	}

	return aRecords
}

func (r *Records) PutCNameRecord(domainName string, cName string, ttl time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.cnameRecords[domainName] == nil {
		r.cnameRecords[domainName] = make(map[string]time.Time)
	}

	r.cnameRecords[domainName][cName] = time.Now().Add(ttl)
}

func (r *Records) PutARecord(domainName string, addr net.IP, ttl time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.aRecords[domainName] == nil {
		r.aRecords[domainName] = make(map[string]time.Time)
	}

	r.aRecords[domainName][string(addr)] = time.Now().Add(ttl)
}

func (r *Records) Cleanup() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for domainName, _ := range r.aRecords {
		for aRecord, ttl := range r.aRecords[domainName] {
			if time.Now().Sub(ttl).Nanoseconds() <= 0 {
				continue
			}
			delete(r.aRecords[domainName], aRecord)
			if len(r.aRecords[domainName]) == 0 {
				delete(r.aRecords, domainName)
				break
			}
		}
	}

	for domainName, _ := range r.cnameRecords {
		for cname, ttl := range r.cnameRecords[domainName] {
			if time.Now().Sub(ttl).Nanoseconds() <= 0 {
				continue
			}
			delete(r.cnameRecords[domainName], cname)
			if len(r.cnameRecords[domainName]) == 0 {
				delete(r.cnameRecords, domainName)
				break
			}
		}
	}
}

func NewRecords() *Records {
	return &Records{
		aRecords:     make(map[string]map[string]time.Time),
		cnameRecords: make(map[string]map[string]time.Time),
	}
}
