package main

import (
	"fmt"
	"net"
	"os"
)

//import (
//	"encoding/binary"
//)

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

const (
	// dnsHeader.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
)

func main() {
	fmt.Println("Hello")
	ServerAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	CheckErr(err)

	ServerCon, err := net.ListenUDP("udp", ServerAddr)
	CheckErr(err)

	defer ServerCon.Close()

	buffer := make([]byte, 4096)

	for {
		n, addr, err := ServerCon.ReadFromUDP(buffer)
		header := dnsHeader{
			Id:      uint16(buffer[0])<<8 | uint16(buffer[1]),
			Bits:    uint16(buffer[2])<<8 | uint16(buffer[3]),
			Qdcount: uint16(buffer[4])<<8 | uint16(buffer[5]),
			Ancount: uint16(buffer[6])<<8 | uint16(buffer[7]),
			Nscount: uint16(buffer[8])<<8 | uint16(buffer[9]),
			Arcount: uint16(buffer[10])<<8 | uint16(buffer[11]),
		}
		fmt.Println("Received ", string(buffer[0:n]), " from ", addr)
		fmt.Println("Packet size: ", n)
		fmt.Println("Is Q: ", header.Bits & _QR)
		fmt.Println("Is AA: ", header.Bits & _AA)
		fmt.Println("Is Truncated: ", header.Bits & _TC)
		fmt.Println("Is RD: ", header.Bits & _RD)
		fmt.Println("Is RA: ", header.Bits & _RA)






		CheckErr(err)

		_, err = ServerCon.WriteToUDP(make([]byte, 3), addr)

	}

}
