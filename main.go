package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	period = "sec"
)

func main() {
	pf := "./file.pcapng"
	h, err := pcap.OpenOffline(pf)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	lens := []int{}
	l := 0
	told := -1
	pSrc := gopacket.NewPacketSource(h, h.LinkType())
	for p := range pSrc.Packets() {
		tnew := p.Metadata().Timestamp.Second()
		if told == -1 || told == tnew {
			l += p.Metadata().Length
		} else {
			lens = append(lens, l)
			l = p.Metadata().Length
		}
		told = tnew
	}
	lens = append(lens, l)

	fmt.Println(lens)
}
