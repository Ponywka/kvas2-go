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

func (r *Records) getCNames(domainName string, recursive bool, reversive bool) []string {
	record, ok := r.Records[domainName]
	if !ok {
		return nil
	}
	if record.Cleanup() {
		delete(r.Records, domainName)
		return nil
	}

	excludedFromCNameList := map[string]struct{}{
		domainName: {},
	}

	cNameList := make([]string, 0)
	for _, cnameRecord := range record.CNameRecords {
		if _, exists := excludedFromCNameList[cnameRecord.CName]; !exists {
			cNameList = append(cNameList, cnameRecord.CName)
			excludedFromCNameList[cnameRecord.CName] = struct{}{}
		}
	}

	if recursive {
		excludedFromProcess := map[string]struct{}{
			domainName: {},
		}

		processingList := cNameList
		for len(processingList) > 0 {
			newProcessingList := []string{}
			for _, cname := range processingList {
				if _, exists := excludedFromProcess[cname]; exists {
					continue
				}

				record, ok := r.Records[cname]
				if !ok {
					continue
				}
				if record.Cleanup() {
					delete(r.Records, cname)
					continue
				}

				for _, cNameRecord := range record.CNameRecords {
					if _, exists := excludedFromCNameList[cNameRecord.CName]; !exists {
						cNameList = append(cNameList, cNameRecord.CName)
						excludedFromCNameList[cNameRecord.CName] = struct{}{}
					}
					newProcessingList = append(newProcessingList, cNameRecord.CName)
				}
			}
			processingList = newProcessingList
		}
	}

	if reversive {
		excludedFromProcess := make(map[string]struct{})
		processingList := []string{domainName}
		for len(processingList) > 0 {
			nextProcessingList := make([]string, 0)
			for _, target := range processingList {
				if _, exists := excludedFromProcess[target]; exists {
					continue
				}

				for cname, record := range r.Records {
					if record.Cleanup() {
						delete(r.Records, cname)
						continue
					}

					for _, cnameRecord := range record.CNameRecords {
						if cnameRecord.CName != target {
							continue
						}

						if _, exists := excludedFromCNameList[record.Name]; !exists {
							cNameList = append(cNameList, record.Name)
							excludedFromCNameList[record.Name] = struct{}{}
						}
						nextProcessingList = append(nextProcessingList, record.Name)
						break
					}
				}

				excludedFromProcess[target] = struct{}{}
			}
			processingList = nextProcessingList
		}
	}

	return cNameList
}

func (r *Records) GetCNameRecords(domainName string, recursive bool, reversive bool) []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.getCNames(domainName, recursive, reversive)
}

func (r *Records) GetARecords(domainName string, recursive bool, reversive bool) []net.IP {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	cNameList := []string{domainName}
	if recursive {
		cNameList = append(cNameList, r.getCNames(domainName, true, reversive)...)
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
