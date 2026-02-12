package checkers

import (
	"errors"
	"log"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func UDPCheck(ip string, port int, host string) bool {
	startTime := time.Now()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   parsedIP,
		Port: port,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return false
	}
	question := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	id := uint16(rand.Intn(65536))
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	builder.EnableCompression()

	if err := builder.StartQuestions(); err != nil {
		return false
	}
	if err := builder.Question(question); err != nil {
		return false
	}

	msg, err := builder.Finish()
	if err != nil {
		return false
	}

	if _, err := conn.Write(msg); err != nil {
		return false
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return false
	}

	buffer := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return false
	}

	var parser dnsmessage.Parser
	respHeader, err := parser.Start(buffer[:n])
	if err != nil {
		return false
	}

	if respHeader.ID != id || !respHeader.Response {
		return false
	}

	if err := parser.SkipAllQuestions(); err != nil {
		return false
	}

	for {
		answer, err := parser.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return false
		}

		if answer.Header.Type == dnsmessage.TypeA {
			if a, ok := answer.Body.(*dnsmessage.AResource); ok {
				ip := net.IP(a.A[:]).String()
				log.Printf("[+] DNS %s response with %s | %dms",
					conn.RemoteAddr(),
					ip,
					time.Since(startTime).Milliseconds(),
				)
				return true
			}
		}
	}

	return false
}
