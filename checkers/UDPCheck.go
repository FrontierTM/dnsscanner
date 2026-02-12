package checkers

import (
	"bytes"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//TODO: I really should add maybe host comparison to prevent poisoning etc

func DOHCheck(host string, resolver string) (check bool) {
	startTime := time.Now()

	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return false
	}

	//Crafting the ID here to compare it later, that's why I didn't feed it directly
	id := uint16(rand.Intn(65536))

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	builder.EnableCompression()

	if err := builder.StartQuestions(); err != nil {
		return false
	}

	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return false
	}

	msg, err := builder.Finish()
	if err != nil {
		return false
	}

	req, err := http.NewRequest("POST", resolver, bytes.NewReader(msg))
	if err != nil {
		return false
	}

	//That's Interesting, isn't it?
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	//Now check the response from the result we got
	var parser dnsmessage.Parser
	header, err := parser.Start(body)
	if err != nil {
		return false
	}

	if header.ID != id || !header.Response {
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
					resolver,
					ip,
					time.Since(startTime).Milliseconds(),
				)
				return true
			}
		}
	}

	return false
}

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

	//Same Story here, Checking the id later
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
