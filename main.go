package main

import (
	"log"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
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

	x := make([]float64, len(lens))
	for i, l := range lens {
		x[i] = float64(l)
	}
	myPlot(x)
}

func myPlot(x []float64) {
	data := make(plotter.XYs, len(x))
	for i := 0; i < len(x); i++ {
		data[i].X = float64(i)
		data[i].Y = x[i]
	}

	p, err := plot.New()
	if err != nil {
		panic(err)
	}

	l, err := plotter.NewLine(data)
	if err != nil {
		panic(err)
	}

	p.Add(l)

	file := "./img/img.png"
	if err = p.Save(10*vg.Inch, 6*vg.Inch, file); err != nil {
		panic(err)
	}

	if err = exec.Command("open", file).Run(); err != nil {
		panic(err)
	}
}
