package dnsProxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

type ResourceRecord interface {
	EncodeResource() []byte
}

type ResourceRecordHeader struct {
	Name  Name
	Type  uint16
	Class uint16
	TTL   uint32
}

func (q ResourceRecordHeader) EncodeHeader() []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(q.Name.Encode())
	buf.Write(binary.BigEndian.AppendUint16([]byte{}, q.Type))
	buf.Write(binary.BigEndian.AppendUint16([]byte{}, q.Class))
	buf.Write(binary.BigEndian.AppendUint32([]byte{}, q.TTL))
	return buf.Bytes()
}

type Name struct {
	Parts []string
}

func (n Name) String() string {
	return strings.Join(n.Parts, ".")
}

func (n Name) Encode() []byte {
	buf := bytes.NewBuffer([]byte{})
	for _, part := range n.Parts {
		partLen := byte(len(part)) & 0x3F
		buf.WriteByte(partLen)
		buf.Write([]byte(part)[0:partLen])
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

type Flags struct {
	QR     uint8
	Opcode uint8
	AA     uint8
	TC     uint8
	RD     uint8
	RA     uint8
	Z1     uint8
	Z2     uint8
	Z3     uint8
	RCode  uint8
}

func (f Flags) Encode() []byte {
	return []byte{
		f.QR&0x1<<7 + f.Opcode&0xF<<3 + f.AA&0x1<<2 + f.TC&0x1<<1 + f.RD&0x1<<0,
		f.RA&0x1<<7 + f.Z1&0x1<<6 + f.Z2&0x1<<5 + f.Z3&0x1<<4 + f.RCode&0xF<<0,
	}
}

type Question struct {
	QName  Name
	QType  uint16
	QClass uint16
}

func (q Question) EncodeQuestion() []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(q.QName.Encode())
	buf.Write(binary.BigEndian.AppendUint16([]byte{}, q.QType))
	buf.Write(binary.BigEndian.AppendUint16([]byte{}, q.QClass))
	return buf.Bytes()
}

type Address struct {
	ResourceRecordHeader
	Address net.IP
}

func (a Address) EncodeResource() []byte {
	rr := bytes.NewBuffer([]byte{})
	rr.Write(a.ResourceRecordHeader.EncodeHeader())
	rr.Write([]byte{0x00, 0x04})
	rr.Write(a.Address[:])
	return rr.Bytes()
}

type NameServer struct {
	ResourceRecordHeader
	NSDName Name
}

func (a NameServer) EncodeResource() []byte {
	rdataBytes := a.NSDName.Encode()
	rr := bytes.NewBuffer([]byte{})
	rr.Write(a.ResourceRecordHeader.EncodeHeader())
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(rdataBytes))))
	rr.Write(rdataBytes)
	return rr.Bytes()
}

type CName struct {
	ResourceRecordHeader
	CName Name
}

func (a CName) EncodeResource() []byte {
	rdataBytes := a.CName.Encode()
	rr := bytes.NewBuffer([]byte{})
	rr.Write(a.ResourceRecordHeader.EncodeHeader())
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(rdataBytes))))
	rr.Write(rdataBytes)
	return rr.Bytes()
}

type Authority struct {
	ResourceRecordHeader
	MName   Name
	RName   Name
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (a Authority) EncodeResource() []byte {
	rdata := bytes.NewBuffer([]byte{})
	rdata.Write(a.MName.Encode())
	rdata.Write(a.RName.Encode())
	rdata.Write(binary.BigEndian.AppendUint32([]byte{}, a.Serial))
	rdata.Write(binary.BigEndian.AppendUint32([]byte{}, a.Refresh))
	rdata.Write(binary.BigEndian.AppendUint32([]byte{}, a.Retry))
	rdata.Write(binary.BigEndian.AppendUint32([]byte{}, a.Expire))
	rdata.Write(binary.BigEndian.AppendUint32([]byte{}, a.Minimum))
	rdataBytes := rdata.Bytes()

	rr := bytes.NewBuffer([]byte{})
	rr.Write(a.ResourceRecordHeader.EncodeHeader())
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(rdataBytes))))
	rr.Write(rdataBytes)
	return rr.Bytes()
}

type Unknown struct {
	ResourceRecordHeader
	Data []byte
}

func (u Unknown) EncodeResource() []byte {
	rr := bytes.NewBuffer([]byte{})
	rr.Write(u.ResourceRecordHeader.EncodeHeader())
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(u.Data))))
	rr.Write(u.Data)
	return rr.Bytes()
}

type Message struct {
	ID    uint16
	Flags Flags
	QD    []Question
	AN    []ResourceRecord
	NS    []ResourceRecord
	AR    []ResourceRecord
}

func (m Message) Encode() []byte {
	rr := bytes.NewBuffer([]byte{})
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, m.ID))
	rr.Write(m.Flags.Encode())
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(m.QD))))
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(m.AN))))
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(m.NS))))
	rr.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(len(m.AR))))
	for _, q := range m.QD {
		rr.Write(q.EncodeQuestion())
	}
	for _, a := range m.AN {
		rr.Write(a.EncodeResource())
	}
	for _, ns := range m.NS {
		rr.Write(ns.EncodeResource())
	}
	for _, a := range m.AR {
		rr.Write(a.EncodeResource())
	}
	return rr.Bytes()
}
