package dnsProxy

import (
	"bytes"
	"testing"
)

func TestDNSResourceRecordHeaderEncode(t *testing.T) {
	recordHeader := ResourceRecordHeader{
		Name:  Name{Parts: []string{"example", "com"}},
		Type:  0xF0,
		Class: 0xF0,
		TTL:   0x77770FF0,
	}
	recordHeaderEncoded := recordHeader.EncodeHeader()
	recordHeaderEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0}
	if bytes.Compare(recordHeaderEncoded, recordHeaderEncodedGood) != 0 {
		t.Fatalf(`ResourceRecordHeader.EncodeHeader() = %x, want "%x", error`, recordHeaderEncoded, recordHeaderEncodedGood)
	}
}

func TestDNSNameString(t *testing.T) {
	dnsName := Name{Parts: []string{"example", "com"}}
	dnsNameString := dnsName.String()
	dnsNameStringGood := "example.com"
	if dnsNameString != dnsNameStringGood {
		t.Fatalf(`Name.String() = %s, want "%s", error`, dnsNameString, dnsNameStringGood)
	}
}

func TestDNSNameEncode(t *testing.T) {
	dnsName := Name{Parts: []string{"example", "com"}}
	dnsNameEncoded := dnsName.Encode()
	dnsNameEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	if bytes.Compare(dnsNameEncoded, dnsNameEncodedGood) != 0 {
		t.Fatalf(`Name.Encode() = %x, want "%x", error`, dnsNameEncoded, dnsNameEncodedGood)
	}
}

func TestDNSFlagsEncode(t *testing.T) {
	dnsFlags := Flags{
		QR:     0x1,
		Opcode: 0xF,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		Z1:     0x0,
		Z2:     0x0,
		Z3:     0x0,
		RCode:  0xF,
	}
	dnsFlagsEncoded := dnsFlags.Encode()
	dnsFlagsEncodedGood := []byte{0xf9, 0x8f}
	if bytes.Compare(dnsFlagsEncoded, dnsFlagsEncodedGood) != 0 {
		t.Fatalf(`Flags.Encode() = %x, want "%x", error`, dnsFlagsEncoded, dnsFlagsEncodedGood)
	}
}

func TestDNSQuestionEncode(t *testing.T) {
	dnsQuestion := Question{
		QName:  Name{Parts: []string{"example", "com"}},
		QType:  0x001c,
		QClass: 0x0001,
	}
	dnsQuestionEncoded := dnsQuestion.EncodeQuestion()
	dnsQuestionEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x1c, 0x00, 0x01}
	if bytes.Compare(dnsQuestionEncoded, dnsQuestionEncodedGood) != 0 {
		t.Fatalf(`Question.EncodeHeader() = %x, want "%x", error`, dnsQuestionEncoded, dnsQuestionEncodedGood)
	}
}

func TestDNSAddressEncode(t *testing.T) {
	dnsAddress := Address{
		ResourceRecordHeader: ResourceRecordHeader{
			Name:  Name{Parts: []string{"example", "com"}},
			Type:  0xF0,
			Class: 0xF0,
			TTL:   0x77770FF0,
		},
		Address: []byte{192, 168, 1, 1},
	}
	dnsAddressEncoded := dnsAddress.EncodeResource()
	dnsAddressEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x04, 192, 168, 1, 1}
	if bytes.Compare(dnsAddressEncoded, dnsAddressEncodedGood) != 0 {
		t.Fatalf(`Address.EncodeResource() = %x, want "%x", error`, dnsAddressEncoded, dnsAddressEncodedGood)
	}
}

func TestDNSNameServerEncode(t *testing.T) {
	dnsNameServer := NameServer{
		ResourceRecordHeader: ResourceRecordHeader{
			Name:  Name{Parts: []string{"example", "com"}},
			Type:  0xF0,
			Class: 0xF0,
			TTL:   0x77770FF0,
		},
		NSDName: Name{Parts: []string{"example", "com"}},
	}
	dnsNameServerEncoded := dnsNameServer.EncodeResource()
	dnsNameServerEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x0D, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	if bytes.Compare(dnsNameServerEncoded, dnsNameServerEncodedGood) != 0 {
		t.Fatalf(`NameServer.EncodeResource() = %x, want "%x", error`, dnsNameServerEncoded, dnsNameServerEncodedGood)
	}
}

func TestDNSCNameEncode(t *testing.T) {
	dnsCName := CName{
		ResourceRecordHeader: ResourceRecordHeader{
			Name:  Name{Parts: []string{"example", "com"}},
			Type:  0xF0,
			Class: 0xF0,
			TTL:   0x77770FF0,
		},
		CName: Name{Parts: []string{"example", "com"}},
	}
	dnsCNameEncoded := dnsCName.EncodeResource()
	dnsCNameEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x0D, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	if bytes.Compare(dnsCNameEncoded, dnsCNameEncodedGood) != 0 {
		t.Fatalf(`CName.EncodeResource() = %x, want "%x", error`, dnsCNameEncoded, dnsCNameEncodedGood)
	}
}

func TestDNSAuthorityEncode(t *testing.T) {
	dnsAuthority := Authority{
		ResourceRecordHeader: ResourceRecordHeader{
			Name:  Name{Parts: []string{"example", "com"}},
			Type:  0xF0,
			Class: 0xF0,
			TTL:   0x77770FF0,
		},
		MName:   Name{Parts: []string{"example", "com"}},
		RName:   Name{Parts: []string{"example", "com"}},
		Serial:  0x12345678,
		Refresh: 0x12345678,
		Retry:   0x12345678,
		Expire:  0x12345678,
		Minimum: 0x12345678,
	}
	dnsAuthorityEncoded := dnsAuthority.EncodeResource()
	dnsAuthorityEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x2E, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78}
	if bytes.Compare(dnsAuthorityEncoded, dnsAuthorityEncodedGood) != 0 {
		t.Fatalf(`Authority.EncodeResource() = %x, want "%x", error`, dnsAuthorityEncoded, dnsAuthorityEncodedGood)
	}
}

func TestDNSUnknownEncode(t *testing.T) {
	dnsUnknown := Unknown{
		ResourceRecordHeader: ResourceRecordHeader{
			Name:  Name{Parts: []string{"example", "com"}},
			Type:  0xF0,
			Class: 0xF0,
			TTL:   0x77770FF0,
		},
		Data: []byte{0x01, 0x02, 0x03},
	}
	dnsUnknownEncoded := dnsUnknown.EncodeResource()
	dnsUnknownEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x03, 0x01, 0x02, 0x03}
	if bytes.Compare(dnsUnknownEncoded, dnsUnknownEncodedGood) != 0 {
		t.Fatalf(`Unknown.EncodeResource() = %x, want "%x", error`, dnsUnknownEncoded, dnsUnknownEncodedGood)
	}
}

//func TestDNSMessageEncode(t *testing.T) {
//	dnsMessage := Message{
//		ID: 0x00FF,
//		Flags: Flags{
//			QR:     0x1,
//			Opcode: 0xF,
//			AA:     0x0,
//			TC:     0x0,
//			RD:     0x1,
//			RA:     0x1,
//			Z1:     0x0,
//			Z2:     0x0,
//			Z3:     0x0,
//			RCode:  0xF,
//		},
//		QD: []Question{
//			{
//				QName:  Name{Parts: []string{"example", "com"}},
//				QType:  0x001c,
//				QClass: 0x0001,
//			},
//		},
//		AN: []ResourceRecord{
//			Unknown{
//				ResourceRecordHeader: ResourceRecordHeader{
//					Name:  Name{Parts: []string{"example", "com"}},
//					Type:  0xF0,
//					Class: 0xF0,
//					TTL:   0x77770FF0,
//				},
//				Data: []byte{0x01, 0x02, 0x03},
//			},
//		},
//		NS: []ResourceRecord{
//			Unknown{
//				ResourceRecordHeader: ResourceRecordHeader{
//					Name:  Name{Parts: []string{"example", "com"}},
//					Type:  0xF0,
//					Class: 0xF0,
//					TTL:   0x77770FF0,
//				},
//				Data: []byte{0x01, 0x02, 0x03},
//			},
//		},
//		AR: []ResourceRecord{
//			Unknown{
//				ResourceRecordHeader: ResourceRecordHeader{
//					Name:  Name{Parts: []string{"example", "com"}},
//					Type:  0xF0,
//					Class: 0xF0,
//					TTL:   0x77770FF0,
//				},
//				Data: []byte{0x01, 0x02, 0x03},
//			},
//		},
//	}
//	dnsMessageEncoded := dnsMessage.Encode()
//	dnsMessageEncodedGood := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0xF0, 0x00, 0xF0, 0x77, 0x77, 0x0F, 0xF0, 0x00, 0x03, 0x01, 0x02, 0x03}
//	if bytes.Compare(dnsMessageEncoded, dnsMessageEncodedGood) != 0 {
//		t.Fatalf(`Message.Encode() = %x, want "%x", error`, dnsMessageEncoded, dnsMessageEncodedGood)
//	}
//}
