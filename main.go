package main

import (
	"bufio"
	"dnsscanner/checkers"
	"dnsscanner/utils"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	serverlist string
	host       string
	output     string
	delay      int
	cidr       string
)

func init() {
	flag.StringVar(&serverlist, "input", "", "A list of DNS servers (IPv4 & DoH)")
	flag.StringVar(&cidr, "cidr", "", "A CIDR range")
	flag.StringVar(&host, "host", "google.com", "A hostname for using in resolve test")
	flag.IntVar(&delay, "delay", 50, "delay beetwen each ip check")
	flag.StringVar(&output, "output", "output.txt", "A file to write results to")
	flag.Parse()
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	fmt.Println("[~] Starting DNSScanner ...")
	filex, err := os.Create(output)
	if err != nil {
		fmt.Println("[X] Error creating file", filex.Name(), ":", err)
		return
	}
	if cidr != "" {
		iplist, _, _ := Hosts(cidr)
		pool := utils.New(1000)
		pool.Start()
		defer pool.Stop()
		for _, sv := range iplist {
			pool.Submit(func() {
				working := checkers.UDPCheck(sv, 53, host)
				if working {
					filex.WriteString(strings.Join([]string{sv, ":", strconv.Itoa(53), "\n"}, ""))
				}
			})
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	if serverlist != "" {
		svlist, err := os.Open(serverlist)
		if err != nil {
			fmt.Println("[X] cant access to server list:", serverlist)
			return
		}
		scanner := bufio.NewScanner(svlist)
		pool := utils.New(1000)
		pool.Start()
		defer pool.Stop()
		for scanner.Scan() {
			server := scanner.Text()
			if strings.HasPrefix(server, "http") {
				// do the fucking DoH (balat nistam hanooz xD)
				continue
			}
			if strings.Contains(server, ":") {
				// IPv6
				continue
			}
			pool.Submit(func() {
				fckstr := server
				port := 53
				working := checkers.UDPCheck(fckstr, port, host)
				if working {
					filex.WriteString(fckstr + "\n")
				}
			})
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

func Hosts(cidr string) ([]string, int, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, lenIPs, nil

	default:
		return ips[1 : len(ips)-1], lenIPs - 2, nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
