package checkers

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

func UDPCheck(ip string, port int, host string) bool {
	con, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		return false
	}
	defer con.Close()
	request := buildRequest(host)
	_, err = con.Write(request)
	if err != nil {
		return false
	}
	defer con.Close()
	response := make([]byte, 1024)
	err = con.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return false
	}
	defer con.Close()
	read, _, err := con.ReadFromUDP(response)
	if err != nil {
		return false
	}
	defer con.Close()
	//fmt.Printf("[+] DNS %s:%d response with %s\n", ip, port, net.IP(response[(read-4):read]))
	fmt.Println("[+] DNS " + con.RemoteAddr().String() + " response with " + net.IP(response[(read-4):read]).To4().String())
	return true
}

func buildRequest(host string) []byte {
	var buf = bytes.Buffer{}
	var prebytes = []byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	buf.Write(prebytes)
	splittedHost := strings.Split(host, ".")
	for _, part := range splittedHost {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)
	return buf.Bytes()
}
