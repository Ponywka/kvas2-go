package dnsProxy

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrInvalidDNSMessageHeader        = errors.New("invalid DNS message header")
	ErrInvalidDNSResourceRecordHeader = errors.New("invalid DNS resource record header")
	ErrInvalidDNSResourceRecordData   = errors.New("invalid DNS resource record data")
	ErrInvalidDNSAddressResourceData  = errors.New("invalid DNS address resource data")
)

func parseName(response []byte, pos int) (Name, int) {
	var nameParts []string
	var jumped bool
	var outPos int
	responseLen := len(response)

	for {
		length := int(response[pos])
		pos++
		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 {
			if !jumped {
				outPos = pos + 1
			}
			pos = int(binary.BigEndian.Uint16(response[pos-1:pos+1]) & 0x3FFF)
			jumped = true
			continue
		}

		if pos+length > responseLen {
			break
		}

		nameParts = append(nameParts, string(response[pos:pos+length]))
		pos += length
	}

	if !jumped {
		outPos = pos
	}
	return Name{Parts: nameParts}, outPos
}

func parseResourceRecord(response []byte, pos int) (ResourceRecord, int, error) {
	responseLen := len(response)

	var rhname Name
	rhname, pos = parseName(response, pos)

	if responseLen < pos+10 {
		return nil, pos, ErrInvalidDNSResourceRecordHeader
	}

	rh := ResourceRecordHeader{
		Name:  rhname,
		Type:  binary.BigEndian.Uint16(response[pos+0 : pos+2]),
		Class: binary.BigEndian.Uint16(response[pos+2 : pos+4]),
		TTL:   binary.BigEndian.Uint32(response[pos+4 : pos+8]),
	}
	rdlength := int(binary.BigEndian.Uint16(response[pos+8 : pos+10]))

	pos += 10

	if pos+rdlength > responseLen {
		return nil, pos, ErrInvalidDNSResourceRecordData
	}

	switch rh.Type {
	case 1:
		if rdlength == 4 {
			return Address{
				ResourceRecordHeader: rh,
				Address:              response[pos+0 : pos+4],
			}, pos + 4, nil
		} else {
			return nil, pos, ErrInvalidDNSAddressResourceData
		}
	case 2:
		var ns Name
		ns, pos = parseName(response, pos)
		return NameServer{
			ResourceRecordHeader: rh,
			NSDName:              ns,
		}, pos, nil
	case 5:
		var cname Name
		cname, pos = parseName(response, pos)
		return CName{
			ResourceRecordHeader: rh,
			CName:                cname,
		}, pos, nil
	}

	return Unknown{
		ResourceRecordHeader: rh,
		Data:                 response[pos+0 : pos+rdlength],
	}, pos + rdlength, nil
}

func ParseResponse(response []byte) (*Message, error) {
	var err error

	responseLen := len(response)
	if responseLen < 12 {
		return nil, ErrInvalidDNSMessageHeader
	}

	msg := new(Message)

	msg.ID = binary.BigEndian.Uint16(response[0:2])

	flagsRAW := binary.BigEndian.Uint16(response[2:4])
	msg.Flags = Flags{
		QR:     uint8(flagsRAW >> 15 & 0x1),
		Opcode: uint8(flagsRAW >> 11 & 0xF),
		AA:     uint8(flagsRAW >> 10 & 0x1),
		TC:     uint8(flagsRAW >> 9 & 0x1),
		RD:     uint8(flagsRAW >> 8 & 0x1),
		RA:     uint8(flagsRAW >> 7 & 0x1),
		Z1:     uint8(flagsRAW >> 6 & 0x1),
		Z2:     uint8(flagsRAW >> 5 & 0x1),
		Z3:     uint8(flagsRAW >> 4 & 0x1),
		RCode:  uint8(flagsRAW >> 0 & 0xF),
	}

	qdCount := int(binary.BigEndian.Uint16(response[4:6]))
	anCount := int(binary.BigEndian.Uint16(response[6:8]))
	nsCount := int(binary.BigEndian.Uint16(response[8:10]))
	arCount := int(binary.BigEndian.Uint16(response[10:12]))

	pos := 12

	msg.QD = make([]Question, qdCount)
	for i := 0; i < qdCount; i++ {
		var name Name
		name, pos = parseName(response, pos)
		msg.QD[i] = Question{
			QName:  name,
			QType:  binary.BigEndian.Uint16(response[pos+0 : pos+2]),
			QClass: binary.BigEndian.Uint16(response[pos+2 : pos+4]),
		}
		pos += 4
	}

	msg.AN = make([]ResourceRecord, anCount)
	for i := 0; i < anCount; i++ {
		msg.AN[i], pos, err = parseResourceRecord(response, pos)
		if err != nil {
			return nil, fmt.Errorf("error while parsing AN record: %w", err)
		}
	}

	msg.NS = make([]ResourceRecord, nsCount)
	for i := 0; i < nsCount; i++ {
		msg.NS[i], pos, err = parseResourceRecord(response, pos)
		if err != nil {
			return nil, fmt.Errorf("error while parsing NS record: %w", err)
		}
	}

	msg.AR = make([]ResourceRecord, arCount)
	for i := 0; i < arCount; i++ {
		msg.AR[i], pos, err = parseResourceRecord(response, pos)
		if err != nil {
			return nil, fmt.Errorf("error while parsing AR record: %w", err)
		}
	}

	return msg, nil
}
