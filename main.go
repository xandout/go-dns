package main

import (
	"fmt"
	"net"
	"os"
	"encoding/binary"
	"bytes"
)

func CheckErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(0)
	}
}

// The wire format for the DNS packet header.
type dnsHeader struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

// DNS queries.
type dnsQuestion struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// DNS responses (resource records).
// There are many types of messages,
// but they all share the same header.
type dnsRR_Header struct {
	Name     string
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
}

type dnsRR_A struct {
	Hdr dnsRR_Header
	A   uint32
}

// Wire constants.
const (
	// valid dnsRR_Header.Rrtype and dnsQuestion.qtype
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeMD    = 3
	dnsTypeMF    = 4
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypeMB    = 7
	dnsTypeMG    = 8
	dnsTypeMR    = 9
	dnsTypeNULL  = 10
	dnsTypeWKS   = 11
	dnsTypePTR   = 12
	dnsTypeHINFO = 13
	dnsTypeMINFO = 14
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33

	// valid dnsQuestion.qtype only
	dnsTypeAXFR  = 252
	dnsTypeMAILB = 253
	dnsTypeMAILA = 254
	dnsTypeALL   = 255

	// valid dnsQuestion.qclass
	dnsClassINET   = 1
	dnsClassCSNET  = 2
	dnsClassCHAOS  = 3
	dnsClassHESIOD = 4
	dnsClassANY    = 255

	// dnsMsg.rcode
	dnsRcodeSuccess        = 0
	dnsRcodeFormatError    = 1
	dnsRcodeServerFailure  = 2
	dnsRcodeNameError      = 3
	dnsRcodeNotImplemented = 4
	dnsRcodeRefused        = 5
)

// Masks to extract info from bits
const (
	// dnsHeader.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
)


var getQType = map[uint16]func() string {
	dnsTypeA: func() string { return "A"},
	dnsTypeNS: func() string { return "NS"},
	dnsTypeMD: func() string { return "MD"},
	dnsTypeMF: func() string { return "MF"},
	dnsTypeCNAME: func() string { return "CNAME"},
	dnsTypeSOA: func() string { return "SOA"},
	dnsTypeMB: func() string { return "MB"},
	dnsTypeMG: func() string { return "MG"},
	dnsTypeMR: func() string { return "MR"},
	dnsTypeNULL: func() string { return "NULL"},
	dnsTypeWKS: func() string { return "WKS"},
	dnsTypePTR: func() string { return "PTR"},
	dnsTypeHINFO: func() string { return "HINFO"},
	dnsTypeMINFO: func() string { return "MINFO"},
	dnsTypeMX: func() string { return "MX"},
	dnsTypeTXT: func() string { return "TXT"},
	dnsTypeAAAA: func() string { return "AAAA"},
	dnsTypeSRV: func() string { return "SRV"},
	dnsTypeAXFR: func() string { return "AXFR"},
	dnsTypeMAILB: func() string { return "MAILB"},
	dnsTypeMAILA: func() string { return "MAILA"},
	dnsTypeALL: func() string { return "ALL"},
}



func main() {
	ServerAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	CheckErr(err)

	ServerCon, err := net.ListenUDP("udp", ServerAddr)
	CheckErr(err)

	defer ServerCon.Close()

	buffer := make([]byte, 4096)

	for {
		n, addr, err := ServerCon.ReadFromUDP(buffer)

		fmt.Println("\n\n")

		header_bytes := buffer[0:12]
		payload_bytes := buffer[13:n]

		final_str_asc := ""
		final_str_hex := ""
		for i := 0; i < len(payload_bytes)-4; i++ {
			if payload_bytes[i] < 31 && payload_bytes[i] != 0 {
				payload_bytes[i] = 46
			}
			final_str_asc += fmt.Sprintf("  %s", string(payload_bytes[i]))
			final_str_hex += fmt.Sprintf("% x", payload_bytes[i])
		}
		
		header := dnsHeader{
			Id:      uint16(header_bytes[0])<<8 | uint16(header_bytes[1]),
			Bits:    uint16(header_bytes[2])<<8 | uint16(header_bytes[3]),
			Qdcount: uint16(header_bytes[4])<<8 | uint16(header_bytes[5]),
			Ancount: uint16(header_bytes[6])<<8 | uint16(header_bytes[7]),
			Nscount: uint16(header_bytes[8])<<8 | uint16(header_bytes[9]),
			Arcount: uint16(header_bytes[10])<<8 | uint16(header_bytes[11]),
		}

		last_byte := len(payload_bytes) - 1
		query := dnsQuestion{
			Name:   string(payload_bytes[0:last_byte-4]),
			Qtype:  uint16(payload_bytes[last_byte-3])<<8 | uint16(payload_bytes[last_byte-2]),
			Qclass: uint16(payload_bytes[last_byte-1])<<8 | uint16(payload_bytes[last_byte]),
		}

		fmt.Println("Packet size: ", n)
		fmt.Println("Is Q: ", header.Bits&_QR)
		fmt.Println("Is AA: ", header.Bits&_AA)
		fmt.Println("Is Truncated: ", header.Bits&_TC)
		fmt.Println("Is RD: ", header.Bits&_RD)
		fmt.Println("Is RA: ", header.Bits&_RA)

		fmt.Println(final_str_asc)
		fmt.Println(final_str_hex)
		fmt.Println(" QUERY: ", query.Name)
		fmt.Println(" QTYPE: ", getQType[query.Qtype]())
		fmt.Println(" QCLASS: ", query.Qclass)

		CheckErr(err)

		rrh := dnsRR_Header{
			Name: query.Name,
			Rrtype: query.Qtype,
			Class: query.Qclass,
			Ttl: uint32(3600),
			Rdlength: 4,
		}

		full_rr := dnsRR_A{
			Hdr: rrh,
			A: binary.BigEndian.Uint32(net.ParseIP("192.168.0.1")),
		}

		newbuf := new(bytes.Buffer)
		binary.Write(newbuf, binary.BigEndian, full_rr)
		newbytes := newbuf.Bytes()

		fmt.Println(newbytes)


		_, err = ServerCon.WriteToUDP(newbytes, addr)

	}

}
