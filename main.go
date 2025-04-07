package main

import (
	"C"
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"slices"
	"time"

	"github.com/VladimiroPaschali/ethtool-indir"
	"github.com/cilium/ebpf/link"
	"github.com/shirou/gopsutil/v3/cpu"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var globalThreshold float64 = 1.0

const MAX_CORES = 32
const MAX_INDIR_SIZE = 256
const INTERVAL = 5

type Config struct {
	Iface       string
	Budget      uint32
	RXQueue     uint32
	CQECompress bool
	Striding    bool
	Weight      [MAX_CORES]uint32
	Cores       uint32
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf cms.bpf.c

func getRing(ethHandle *ethtool.Ethtool, iface string) ethtool.Ring {
	ring, err := ethHandle.GetRing(iface)
	if err != nil {
		panic(err.Error())
	}
	// fmt.Printf("Ring: %v\n", ring.RxPending)
	return ring
}

func setRing(ethHandle *ethtool.Ethtool, iface string, ring ethtool.Ring) ethtool.Ring {
	ring, err := ethHandle.SetRing(iface, ring)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("Ring RxPending: %v, TxPending: %v\n", ring.RxPending, ring.TxPending)
	return ring
}

func setConfig(ethHandle *ethtool.Ethtool, config Config) {
	// meglio settare prima le flag perche  settare il ring crea una nuova napi
	oldPriv, err := ethHandle.PrivFlags(config.Iface)
	if err != nil {
		panic(err.Error())
	}

	newPriv := oldPriv
	newPriv["rx_cqe_compress"] = config.CQECompress
	newPriv["rx_striding_rq"] = config.Striding

	err = ethHandle.UpdatePrivFlags(config.Iface, newPriv)
	if err != nil {
		panic(err.Error())
	}

	ring := getRing(ethHandle, config.Iface)
	ring.TxPending = config.Budget
	ring.RxPending = config.RXQueue
	ring = setRing(ethHandle, config.Iface, ring)

}

func getIndir(ethHandle *ethtool.Ethtool, iface string) [256]uint32 {
	indir, err := ethHandle.GetIndir(iface)
	if err != nil {
		panic(err.Error())
	}
	return indir.RingIndex
}

func setIndir(ethHandle *ethtool.Ethtool, config Config) {
	setindir := ethtool.SetIndir{}
	setindir.Weight = config.Weight

	_, err := ethHandle.SetIndir(config.Iface, setindir)
	if err != nil {
		panic(err.Error())
	}
}

func overrideIndir(ethHandle *ethtool.Ethtool, iface string, indir ethtool.SetIndir) {
	_, err := ethHandle.SetIndir(iface, indir)
	if err != nil {
		panic(err.Error())
	}
}

func getDrop(ethHandle *ethtool.Ethtool, iface string, seconds int) uint64 {

	var duration time.Duration = time.Duration(seconds) * time.Second

	stats, err := ethHandle.Stats(iface)
	if err != nil {
		panic(err.Error())
	}
	// fmt.Printf("rx_xdp_drop: %d\n", stats["rx_xdp_drop"])
	var pre uint64 = stats["rx_xdp_drop"]

	time.Sleep(duration)

	stats, err = ethHandle.Stats(iface)
	if err != nil {
		panic(err.Error())
	}
	// fmt.Printf("rx_xdp_drop: %d\n", stats["rx_xdp_drop"])
	var post uint64 = stats["rx_xdp_drop"]
	var tot uint64 = post - pre
	var pps uint64 = tot / uint64(seconds)

	p := message.NewPrinter(language.English)
	p.Printf("Drop per second %d\n", pps)

	return pps
}

func createCSV() *csv.Writer {
	file, err := os.Create("results.csv")
	if err != nil {
		panic(err.Error())
	}

	writer := csv.NewWriter(file)

	err = writer.Write([]string{"budget", "rxqueue", "rx_cqe_compress", "rx_striding_rq", "rx_xdp_drop", "cpu", "core_count", "time"})
	if err != nil {
		file.Close()
		panic(err.Error())
	}

	writer.Flush()

	return writer
}

func writeCSV(writer *csv.Writer, config Config, drop uint64, cpu int) {
	now := time.Now()
	p := message.NewPrinter(language.English)
	p.Printf("budget: %d, rxqueue: %d, cqe_compress: %t, striding: %t, drop: %d, cpu: %d, core_count %d, time: %s\n", config.Budget, config.RXQueue, config.CQECompress, config.Striding, drop, cpu, config.Cores, now.Format("15:04:05"))

	err := writer.Write([]string{fmt.Sprintf("%d", config.Budget), fmt.Sprintf("%d", config.RXQueue), fmt.Sprintf("%t", config.CQECompress), fmt.Sprintf("%t", config.Striding), fmt.Sprintf("%d", drop), fmt.Sprintf("%d", cpu), fmt.Sprintf("%d", config.Cores), now.Format("15:04:05")})
	if err != nil {
		panic(err.Error())
	}
	writer.Flush()

}

// attachXDP carica e attacca il programma XDP all'interfaccia specificata
func attachXDP(iface string) link.Link {

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ifnum, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", iface, err)
	}

	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Cms,
		Interface: ifnum.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}

	fmt.Printf("Programma XDP attaccato a %s\n", iface)
	return xdpLink
}

func getCPUPercentage(core int) int {
	percentages, err := cpu.Percent(time.Second, true)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("CPU %d usage: %d\n", core, int(math.Round(percentages[core])))
	return int(math.Round(percentages[core]))
}

func getAverageCPUPercentage(weight [MAX_CORES]uint32) int {
	percentages, err := cpu.Percent(time.Second, true)
	if err != nil {
		panic(err.Error())
	}
	var sum float64
	var numcores int
	for index, p := range percentages {
		if weight[index] > 0 {
			// fmt.Printf("CPU %d usage: %d\n", index, int(math.Round(p)))
			sum += p
			numcores++
		}
	}
	avg := int(math.Round(sum / float64(numcores)))
	// fmt.Printf("CPU usage: %v\n", percentages)
	// fmt.Printf("Average CPU usage: %d\n", avg)
	return avg
}

/*
test and update the current RX Queue size if there is a gain in throughput
*/
func changeRxQueue(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {
	var listRxQueue = []uint32{128, 256, 512, 1024, 2048, 4096, 8192}
	old := getDrop(ethHandle, config.Iface, interval)
	var next uint64
	var prev uint64
	var maxDrop uint64

	oldRxQueueIndex := slices.Index(listRxQueue, config.RXQueue)
	prevRxQueueIndex := oldRxQueueIndex - 1
	nexRxQueueIndex := oldRxQueueIndex + 1

	if prevRxQueueIndex >= 0 {
		config.RXQueue = listRxQueue[prevRxQueueIndex]
		setConfig(ethHandle, config)
		prev = getDrop(ethHandle, config.Iface, interval)
	}
	if nexRxQueueIndex <= len(listRxQueue) {

		config.RXQueue = listRxQueue[nexRxQueueIndex]
		setConfig(ethHandle, config)
		next = getDrop(ethHandle, config.Iface, interval)
	}

	fmt.Printf("Old %d, Next %d, Prev %d, extern %d\n", old, next, prev, extDrop)

	// maggiore di quello non modificato e del massimo totale
	if float64(prev) > float64(next)*globalThreshold && float64(prev) > float64(old)*globalThreshold && float64(prev) > float64(extDrop)*globalThreshold {
		fmt.Printf("Lower Rxqueue %d is better\n", listRxQueue[prevRxQueueIndex])
		config.RXQueue = listRxQueue[prevRxQueueIndex]
		setConfig(ethHandle, config)
		maxDrop = prev
	} else if float64(next) > float64(prev)*globalThreshold && float64(next) > float64(old)*globalThreshold && float64(next) > float64(extDrop)*globalThreshold {
		fmt.Printf("Higher Rxqueue %d is better\n", listRxQueue[nexRxQueueIndex])
		config.RXQueue = listRxQueue[nexRxQueueIndex]
		setConfig(ethHandle, config)
		maxDrop = next
	} else {
		fmt.Printf("Current Rxqueue %d is better\n", listRxQueue[oldRxQueueIndex])
		setConfig(ethHandle, config)
		config.RXQueue = listRxQueue[oldRxQueueIndex]
		maxDrop = old

	}

	return config, maxDrop

}

/*
test and update the current RX budget size if there is a gain in throughput
*/
func changeRxBudget(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {
	var listBudget = []uint32{2, 4, 8, 16, 32, 64, 128, 256, 512}
	old := getDrop(ethHandle, config.Iface, interval)
	var next uint64
	var prev uint64
	var maxDrop uint64

	oldBudgetIndex := slices.Index(listBudget, config.Budget)
	prevBudgetIndex := oldBudgetIndex - 1
	nexBudgetIndex := oldBudgetIndex + 1

	if prevBudgetIndex > 0 {
		config.Budget = listBudget[prevBudgetIndex]
		setConfig(ethHandle, config)
		prev = getDrop(ethHandle, config.Iface, interval)
	}
	if nexBudgetIndex < len(listBudget) {
		config.Budget = listBudget[nexBudgetIndex]
		setConfig(ethHandle, config)
		next = getDrop(ethHandle, config.Iface, interval)
	}

	fmt.Printf("Old %d, Next %d, Prev %d, extern %d\n", old, next, prev, extDrop)

	if float64(prev) > float64(next)*globalThreshold && float64(prev) > float64(old)*globalThreshold && float64(prev) > float64(extDrop)*globalThreshold {
		fmt.Printf("Lower Budget %d is better\n", listBudget[prevBudgetIndex])
		config.Budget = listBudget[prevBudgetIndex]
		setConfig(ethHandle, config)
		maxDrop = prev
	} else if float64(next) > float64(prev)*globalThreshold && float64(next) > float64(old)*globalThreshold && float64(next) > float64(extDrop)*globalThreshold {
		fmt.Printf("Higher Budget %d is better\n", listBudget[nexBudgetIndex])
		config.Budget = listBudget[nexBudgetIndex]
		setConfig(ethHandle, config)
		maxDrop = next
	} else {
		fmt.Printf("Current Budget %d is better\n", listBudget[oldBudgetIndex])
		config.Budget = listBudget[oldBudgetIndex]
		setConfig(ethHandle, config)
		maxDrop = old
	}
	return config, maxDrop
}

func changeCqeCompress(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {

	old := getDrop(ethHandle, config.Iface, interval)

	oldCQECompress := config.CQECompress
	newCQECompress := !oldCQECompress
	var maxDrop uint64

	config.CQECompress = newCQECompress
	setConfig(ethHandle, config)

	new := getDrop(ethHandle, config.Iface, interval)
	if float64(new) > float64(old)*globalThreshold && float64(new) > float64(extDrop)*globalThreshold {
		fmt.Printf("New Cqe Compression %t more than prevoius\n", newCQECompress)
		maxDrop = new
	} else {
		fmt.Printf("Previous Cqe Compression %t less than prevoius reverting\n", oldCQECompress)
		config.CQECompress = oldCQECompress
		setConfig(ethHandle, config)
		maxDrop = old
	}
	return config, maxDrop
}

func changeRxStriding(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {

	old := getDrop(ethHandle, config.Iface, interval)

	oldRxStriding := config.Striding
	newRxStriding := !oldRxStriding
	var maxDrop uint64

	config.Striding = newRxStriding
	setConfig(ethHandle, config)

	new := getDrop(ethHandle, config.Iface, interval)
	if float64(new) > float64(old)*globalThreshold && float64(new) > float64(extDrop)*globalThreshold {
		fmt.Printf("New Rx striding %t more than prevoius\n", newRxStriding)
		maxDrop = new
	} else {
		fmt.Printf("Prevous Rx striding %t less than prevoius reverting\n", oldRxStriding)
		config.Striding = oldRxStriding
		setConfig(ethHandle, config)
		maxDrop = old
	}
	return config, maxDrop
}

func createSlice(ones uint32, start uint32) [MAX_CORES]uint32 {
	var slice [MAX_CORES]uint32
	for i := start; i < ones; i++ {
		slice[i] = 1
	}
	return slice
}

func changeCPUCount(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {

	var maxDrop uint64

	percentage := getAverageCPUPercentage(config.Weight)
	if percentage > 80 && config.Cores < MAX_CORES {
		config.Weight = createSlice(config.Cores+1, 0)
		config.Cores++
	} else if percentage < 60 && config.Cores > 1 {
		config.Weight = createSlice(config.Cores-1, 0)
		config.Cores--
	}

	setIndir(ethHandle, config)
	new := getDrop(ethHandle, config.Iface, interval)
	maxDrop = new
	return config, maxDrop
}

func main() {

	writer := createCSV()

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		panic(err.Error())
	}
	defer ethHandle.Close()

	config := Config{
		Iface:       "enp52s0f1np1",
		Budget:      64,
		RXQueue:     1024,
		CQECompress: true,
		Striding:    true,
		Weight:      [32]uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		Cores:       10,
	}
	setConfig(ethHandle, config)
	setIndir(ethHandle, config)

	var drop uint64

	xdpLink := attachXDP(config.Iface)
	defer xdpLink.Close()

	//baseline
	drop = getDrop(ethHandle, config.Iface, INTERVAL)
	writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

	for {
		drop = 0

		config, drop = changeRxQueue(ethHandle, config, INTERVAL, drop)
		writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

		config, drop = changeRxBudget(ethHandle, config, INTERVAL, drop)
		writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

		config, drop = changeCqeCompress(ethHandle, config, INTERVAL, drop)
		writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

		config, drop = changeRxStriding(ethHandle, config, INTERVAL, drop)
		writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

		config, drop = changeCPUCount(ethHandle, config, INTERVAL, drop)
		writeCSV(writer, config, drop, getAverageCPUPercentage(config.Weight))

	}

}
