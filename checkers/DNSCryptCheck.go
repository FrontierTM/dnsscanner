package checkers

import (
	"log"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

func SDNCheck(host string, url string) (check bool) {
	startTime := time.Now()
	c := dnscrypt.Client{Net: "udp", Timeout: 10 * time.Second}

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   dns.Fqdn(host),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}

	resolverInfo, err := c.Dial(url)
	if err != nil {
		return false
	}

	reply, err := c.Exchange(&req, resolverInfo)
	if err != nil || reply == nil {
		return false
	}

	for _, ans := range reply.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			log.Printf("[+] DNS %s response with %s | %dms",
				url,
				aRecord.A.String(),
				time.Since(startTime).Milliseconds(),
			)
			return true
		}
	}
	return false
}
