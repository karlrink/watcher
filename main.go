package main

import (
	//"bufio"
	"fmt"
	"log"
	//"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

    "gitlab.com/krink/logstream/golang/logstream"
)

const thresh = 60
const attempts = 1
const clear = 86400
const tcpPort = 465

var iplist = make([]string, attempts)
var tmlist = make([]int64, attempts)
var blocklist = make([]string, 0)
var blocktime = make([]int64, 0)


func recordIP(ip string, tm int64) {
    fmt.Printf("recordIP " + ip)
	iplist = append([]string{ip}, iplist[:len(iplist)-1]...)
	tmlist = append([]int64{tm}, tmlist[:len(tmlist)-1]...)
}

func recordBlock(ip string, tm int64) {
	blocklist = append([]string{ip}, blocklist...)
	blocktime = append([]int64{tm}, blocktime...)
}

func compare() int {
	count := 0
	for _, item := range iplist {
		if item == iplist[0] {
			count++
		}
	}
	return count
}

func ipBlock(ip string, tm int64) {
	cmd := fmt.Sprintf("iptables -I INPUT -s %s -p tcp --dport %d -j DROP", ip, tcpPort)
	exec.Command("bash", "-c", cmd).Run()
	log.Printf(cmd)
	recordBlock(ip, tm)
}

func ipRemove(ip string) {
	cmd := fmt.Sprintf("iptables -D INPUT -s %s -p tcp --dport %d -j DROP", ip, tcpPort)
	exec.Command("bash", "-c", cmd).Run()
	log.Printf(cmd)
}

func checkBlocklist() {
	for {
		if len(blocklist) > 0 {
			now := time.Now().Unix()
			for index, item := range blocktime {
				diff := now - item
				if diff > clear {
					ip := blocklist[index]
					ipRemove(ip)
					blocklist = append(blocklist[:index], blocklist[index+1:]...)
					blocktime = append(blocktime[:index], blocktime[index+1:]...)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}



func main() {

    reSASLFailedPassword := regexp.MustCompile(`SASL LOGIN authentication failed`)
    reIP := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`) // Regexp to extract IP

    go checkBlocklist()

    output, err := logstream.Syslog()
    if err != nil {
        fmt.Println("Failed to get output:", err)
        return
    }

    // Process the captured output
    for line := range output {
        if reSASLFailedPassword.MatchString(line) {
            fmt.Println(line)
            ipField := strings.Fields(line)[6]
            ipMatches := reIP.FindStringSubmatch(ipField)
            if len(ipMatches) == 0 {
                log.Println("No IP found in line:", line)
                continue
            }
            ip := ipMatches[0] // This is the extracted IP address
            fmt.Println(ip)

            tm := time.Now().Unix()
            recordIP(ip, tm)

            if compare() >= len(iplist) {
                elapsed := tmlist[0] - tmlist[len(tmlist)-1]
                if thresh > elapsed {
                    ipBlock(ip, tm)
                    log.Printf("ip: %s will clear in %d", ip, clear)
                }
            }
        }
    }
}



