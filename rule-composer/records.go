package ruleComposer

import (
	"bytes"
	"net"
	"sync"
	"time"
)

type Records struct {
	mutex         sync.RWMutex
	ipv4Addresses map[string]map[string]time.Time
	cNames        map[string]map[string]time.Time
}

func (r *Records) getCNames(domainName string) []string {
	_, ok := r.cNames[domainName]
	if !ok {
		return nil
	}

	cNameList := make([]string, 0, len(r.cNames[domainName]))
	for cname, ttl := range r.cNames[domainName] {
		if time.Now().Sub(ttl).Nanoseconds() < 0 {
			cNameList = append(cNameList, cname)
		}
	}

	origCNameLen := len(cNameList)
	for i := 0; i < origCNameLen; i++ {
		parentList := r.getCNames(cNameList[i])
		if parentList != nil {
			cNameList = append(cNameList, parentList...)
		}
	}

	return cNameList
}

func (r *Records) GetIPv4Addresses(domainName string) []net.IP {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	cNameList := append([]string{domainName}, r.getCNames(domainName)...)
	ipAddresses := make([]net.IP, 0)
	for _, cName := range cNameList {
		addresses, ok := r.ipv4Addresses[cName]
		if !ok {
			continue
		}

		addressesNetIP := make([]net.IP, 0, len(addresses))
		for addr, ttl := range addresses {
			if time.Now().Sub(ttl).Nanoseconds() < 0 {
				addressesNetIP = append(addressesNetIP, []byte(addr))
			}
		}

		ipAddresses = append(ipAddresses, addressesNetIP...)
	}

	return ipAddresses
}

func (r *Records) PutCName(domainName string, cName string, ttl int64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.cNames[domainName] == nil {
		r.cNames[domainName] = make(map[string]time.Time)
	}

	skipPut := false
	for name, _ := range r.cNames[domainName] {
		if name == cName {
			r.cNames[domainName][name] = time.Now().Add(time.Second * time.Duration(ttl))
			skipPut = true
			break
		}
	}

	if !skipPut {
		r.cNames[domainName][cName] = time.Now().Add(time.Second * time.Duration(ttl))
	}
}

func (r *Records) PutIPv4Address(domainName string, addr net.IP, ttl int64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.ipv4Addresses[domainName] == nil {
		r.ipv4Addresses[domainName] = make(map[string]time.Time)
	}

	skipPut := false
	for address, _ := range r.ipv4Addresses[domainName] {
		if bytes.Compare([]byte(address), addr) == 0 {
			r.ipv4Addresses[domainName][address] = time.Now().Add(time.Second * time.Duration(ttl))
			skipPut = true
			break
		}
	}

	if !skipPut {
		r.ipv4Addresses[domainName][string(addr)] = time.Now().Add(time.Second * time.Duration(ttl))
	}
}

func NewRecords() *Records {
	return &Records{
		ipv4Addresses: make(map[string]map[string]time.Time),
		cNames:        make(map[string]map[string]time.Time),
	}
}
