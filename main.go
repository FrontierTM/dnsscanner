package main

import (
	"bufio"
	"dnsscanner/checkers"
	"dnsscanner/utils"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	ServerList string
	Host       string
	Delay      int
	Thread     int
	Cidr       string
)

func init() {
	flag.StringVar(&ServerList, "input", "input.txt", "A list of DNS servers (IPv4 & DoH)")
	flag.StringVar(&Cidr, "cidr", "", "A CIDR range")
	flag.StringVar(&Host, "host", "google.com", "A hostname for using in resolve test")
	flag.IntVar(&Delay, "delay", 50, "Delay beetwen each ip check")
	flag.IntVar(&Thread, "thread", 10000, "total Thread for worker")
	flag.Parse()
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	fmt.Println("[~] Starting DNSScanner ...")

	now := time.Now()
	date := now.Format("2006-01-02")
	clock := now.Format("15-04-05")

	dir := filepath.Join("result", date, clock)

	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	filePath := filepath.Join(dir, "result.txt")

	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("[X] Error creating file:", err)
		return
	}
	defer file.Close()

	pool := utils.New(Thread)
	pool.Start()
	defer pool.Stop()

	if Cidr != "" {
		ipList, _, _ := Hosts(Cidr)

		for _, sv := range ipList {
			pool.Submit(func() {
				if checkers.UDPCheck(sv, 53, Host) {
					file.WriteString(strings.Join([]string{sv, ":", strconv.Itoa(53), "\n"}, ""))
				}
			})
			time.Sleep(time.Duration(Delay) * time.Millisecond)
		}
	}

	if ServerList != "" {
		svlist, err := os.Open(ServerList)
		if err != nil {
			fmt.Println("[X] cant access to server list:", ServerList)
			return
		}
		scanner := bufio.NewScanner(svlist)

		for scanner.Scan() {
			server := scanner.Text()
			if strings.HasPrefix(server, "https") {
				pool.Submit(func() {
					checkers.DOHCheck(Host, server)
					file.WriteString(server)

				})
				continue
			}
			if strings.Contains(server, ":") {
				// IPv6
				continue
			}
			pool.Submit(func() {
				working := checkers.UDPCheck(server, 53, Host)
				if working {
					file.WriteString(server + "\n")
				}
			})
			time.Sleep(time.Duration(Delay) * time.Millisecond)
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
