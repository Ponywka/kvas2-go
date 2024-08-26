package main

import (
	"bytes"
	"net"
	"slices"
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
	CName    string
	Deadline time.Time
}

func NewCNameRecord(domainName string, deadline time.Time) *CNameRecord {
	return &CNameRecord{
		CName:    domainName,
		Deadline: deadline,
	}
}

type Record struct {
	Name         string
	ARecords     []*ARecord
	CNameRecords []*CNameRecord
}

func (r *Record) Cleanup() bool {
	newARecords := make([]*ARecord, 0)
	for _, record := range r.ARecords {
		if time.Now().Sub(record.Deadline).Nanoseconds() <= 0 {
			newARecords = append(newARecords, record)
		}
	}
	r.ARecords = newARecords

	newCNameRecords := make([]*CNameRecord, 0)
	for _, record := range r.CNameRecords {
		if time.Now().Sub(record.Deadline).Nanoseconds() <= 0 {
			newCNameRecords = append(newCNameRecords, record)
		}
	}
	r.CNameRecords = newCNameRecords

	return len(newARecords) == 0 && len(newCNameRecords) == 0
}

func NewRecord(domainName string) *Record {
	return &Record{
		Name:         domainName,
		ARecords:     make([]*ARecord, 0),
		CNameRecords: make([]*CNameRecord, 0),
	}
}

type Records struct {
	mutex   sync.RWMutex
	Records map[string]*Record
}

func (r *Records) getCNames(domainName string, recursive bool, excludeDomains ...string) []string {
	record, ok := r.Records[domainName]
	if !ok {
		return nil
	}
	if record.Cleanup() {
		delete(r.Records, domainName)
		return nil
	}

	cNameList := make([]string, len(record.CNameRecords))
	for idx, cnameRecord := range record.CNameRecords {
		cNameList[idx] = cnameRecord.CName
	}

	if recursive {
		origCNameLen := len(cNameList)
		for i := 0; i < origCNameLen; i++ {
			if slices.Contains(excludeDomains, cNameList[i]) {
				continue
			}

			excludeDomains = append(excludeDomains, cNameList...)
			parentList := r.getCNames(cNameList[i], true, excludeDomains...)
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
		record, ok := r.Records[cName]
		if !ok {
			continue
		}
		if record.Cleanup() {
			delete(r.Records, cName)
			continue
		}

		for _, aRecord := range record.ARecords {
			aRecords = append(aRecords, aRecord.Address)
		}
	}

	return aRecords
}

func (r *Records) PutCNameRecord(domainName string, cName string, ttl time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	record, ok := r.Records[domainName]
	if !ok {
		record = NewRecord(domainName)
		r.Records[domainName] = record
	}
	record.Cleanup()

	for _, cNameRecord := range record.CNameRecords {
		if cNameRecord.CName == cName {
			cNameRecord.Deadline = time.Now().Add(ttl)
			return
		}
	}

	record.CNameRecords = append(record.CNameRecords, NewCNameRecord(cName, time.Now().Add(ttl)))
}

func (r *Records) PutARecord(domainName string, addr net.IP, ttl time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	record, ok := r.Records[domainName]
	if !ok {
		record = NewRecord(domainName)
		r.Records[domainName] = record
	}
	record.Cleanup()

	for _, aRecord := range record.ARecords {
		if bytes.Compare(aRecord.Address, addr) == 0 {
			aRecord.Deadline = time.Now().Add(ttl)
			return
		}
	}
	record.ARecords = append(record.ARecords, NewARecord(addr, time.Now().Add(ttl)))
}

func (r *Records) Cleanup() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for domainName, record := range r.Records {
		if record.Cleanup() {
			delete(r.Records, domainName)
		}
	}
}

func NewRecords() *Records {
	return &Records{
		Records: make(map[string]*Record),
	}
}
