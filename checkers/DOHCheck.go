package checkers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func DOHCheck(host string, resolver string) {
	startTime := time.Now()

	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return
	}

	//Crafting the ID here to compare it later, that's why I didn't feed it directly
	id := uint16(rand.Intn(65536))

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	builder.EnableCompression()

	if err := builder.StartQuestions(); err != nil {
		return
	}

	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return
	}

	msg, err := builder.Finish()
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", resolver, bytes.NewReader(msg))
	if err != nil {
		return
	}

	//That's Interesting, isn't it?
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	//Now check the response from the result we got
	var parser dnsmessage.Parser
	header, err := parser.Start(body)
	if err != nil {
		return
	}

	if header.ID != id || !header.Response {
		return
	}

	if err := parser.SkipAllQuestions(); err != nil {
		return
	}

	for {
		answer, err := parser.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return
		}

		if answer.Header.Type == dnsmessage.TypeA {
			if a, ok := answer.Body.(*dnsmessage.AResource); ok {
				ip := net.IP(a.A[:]).String()
				estimated := time.Now().Sub(startTime).Milliseconds()
				result := fmt.Sprintf("[+] DNS %s response with %s | %dms",
					resolver,
					ip,
					estimated)

				log.Println(result)
			}
		}
	}

	return
}
