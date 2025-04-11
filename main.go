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
	"github.com/u-root/u-root/pkg/msr"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// var PPS_THRESHOLD float64 = 1.0001 // 7 mila su 7 milioni
const PPS_THRESHOLD float64 = 1 // 7 mila su 7 milioni
const DROPPED_THRESHOLD = 100
const MAX_CORES = 32
const MAX_INDIR_SIZE = 256
const INTERVAL = 5

type Config struct {
	Iface       string
	Action      string
	Budget      uint32
	RXQueue     uint32
	CQECompress bool
	Striding    bool
	Weight      [MAX_CORES]uint32
	Cores       uint32
	MSR         uint32
	MSRValue    uint64
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
	// fmt.Printf("Ring RxPending: %v, TxPending: %v\n", ring.RxPending, ring.TxPending)
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
func setMSR(val uint64) {
	c, err := msr.AllCPUs()
	if err != nil {
		panic(err)
	}
	var r msr.MSR = 0xc8b
	r.Write(c, val)
	// fmt.Printf("Set MSR to %x\n", val)

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
	setindir.Weight = config.Weight[:]
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

func equalizeIndir(ethHandle *ethtool.Ethtool, config Config, minCPU uint32, maxCPU uint32) {
	oldIndir := getIndir(ethHandle, config.Iface)
	for index, value := range oldIndir {
		// if value == maxCPU && index%2 == 0 {
		if value == maxCPU && index%5 == 0 {

			oldIndir[index] = minCPU
		}
	}
	// variabile indir
	newIndir := ethtool.SetIndir{}
	newIndir.RingIndex = oldIndir
	overrideIndir(ethHandle, config.Iface, newIndir)
}

func getAction(ethHandle *ethtool.Ethtool, iface string, seconds int, action string) uint64 {

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

	// p := message.NewPrinter(language.English)
	// p.Printf("Drop per second %d\n", pps)

	return pps
}

func getNotProcessed(ethHandle *ethtool.Ethtool, iface string, seconds int, action string) int {
	var duration time.Duration = time.Duration(seconds) * time.Second

	stats, err := ethHandle.Stats(iface)
	if err != nil {
		panic(err.Error())
	}
	// fmt.Printf("rx_xdp_drop: %d\n", stats["rx_xdp_drop"])
	var prePhy uint64 = stats["rx_packets_phy"]
	var preAction uint64 = stats[action]

	time.Sleep(duration)

	stats, err = ethHandle.Stats(iface)
	if err != nil {
		panic(err.Error())
	}
	// fmt.Printf("rx_xdp_drop: %d\n", stats["rx_xdp_drop"])
	var postPhy uint64 = stats["rx_packets_phy"]
	var postAction uint64 = stats[action]
	var totPhy uint64 = postPhy - prePhy
	var totAction uint64 = postAction - preAction
	var ppsPhy uint64 = totPhy / uint64(seconds)
	var ppsAction uint64 = totAction / uint64(seconds)
	var pps uint64 = ppsPhy - ppsAction

	// p := message.NewPrinter(language.English)
	// p.Printf("Not Processed per second %d\n", int(pps))

	return int(pps)
}

func createCSV() *csv.Writer {
	file, err := os.Create("results.csv")
	if err != nil {
		panic(err.Error())
	}

	writer := csv.NewWriter(file)

	err = writer.Write([]string{"budget", "rxqueue", "rx_cqe_compress", "rx_striding_rq", "rx_xdp_drop", "msr", "cpu", "core_count", "time"})
	if err != nil {
		file.Close()
		panic(err.Error())
	}

	writer.Flush()

	return writer
}

func writeCSV(writer *csv.Writer, config Config, drop uint64, cpu float64) {
	now := time.Now()
	p := message.NewPrinter(language.English)
	p.Printf("budget: %d, rxqueue: %d, cqe_compress: %t, striding: %t, drop: %d, msr: %x cpu: %f, core_count %d, time: %s\n", config.Budget, config.RXQueue, config.CQECompress, config.Striding, drop, config.MSRValue, cpu, config.Cores, now.Format("15:04:05"))

	err := writer.Write([]string{fmt.Sprintf("%d", config.Budget), fmt.Sprintf("%d", config.RXQueue), fmt.Sprintf("%t", config.CQECompress), fmt.Sprintf("%t", config.Striding), fmt.Sprintf("%d", drop), fmt.Sprintf("%x", config.MSRValue), fmt.Sprintf("%f", cpu), fmt.Sprintf("%d", config.Cores), now.Format("15:04:05")})
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

func getAverageCPUPercentage(weight [MAX_CORES]uint32) float64 {
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
	// avg := int(math.Round(sum / float64(numcores)))
	avg := sum / float64(numcores)
	// fmt.Printf("CPU usage: %v\n", percentages)
	// fmt.Printf("Average CPU usage: %d\n", avg)
	return avg
}

/*
test and update the current RX Queue size if there is a gain in throughput
*/
func changeRxQueue(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64, float64) {
	var listRxQueue = []uint32{128, 256, 512, 1024, 2048, 4096, 8192}

	oldPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	oldCPU := getAverageCPUPercentage(config.Weight)
	oldNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)

	var nextPPS uint64
	var nextCPU float64
	var nextNotProcessed int
	var prevPPS uint64
	var prevCPU float64
	var prevNotProcessed int
	var bestPPS uint64
	var bestCPU float64

	oldRxQueueIndex := slices.Index(listRxQueue, config.RXQueue)
	prevRxQueueIndex := oldRxQueueIndex - 1
	nexRxQueueIndex := oldRxQueueIndex + 1

	//gathers data for the different RXQueue sizes
	if prevRxQueueIndex >= 0 {
		config.RXQueue = listRxQueue[prevRxQueueIndex]
		setConfig(ethHandle, config)
		prevPPS = getAction(ethHandle, config.Iface, interval, config.Action)
		prevCPU = getAverageCPUPercentage(config.Weight)
		prevNotProcessed = getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	}
	if nexRxQueueIndex <= len(listRxQueue) {

		config.RXQueue = listRxQueue[nexRxQueueIndex]
		setConfig(ethHandle, config)
		nextPPS = getAction(ethHandle, config.Iface, interval, config.Action)
		nextCPU = getAverageCPUPercentage(config.Weight)
		nextNotProcessed = getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	}

	// fmt.Printf("Old %d, Next %d, Prev %d, extern %d\n", old, next, prev, extDrop)

	p := message.NewPrinter(language.English)
	type candidate struct {
		rxQueueIndex int
		pps          uint64
		cpu          float64
		name         string
	}

	var candidates []candidate

	// Raccogli solo le configurazioni che processano tutto
	if oldNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{oldRxQueueIndex, oldPPS, oldCPU, "Old"})
	}
	if prevNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{prevRxQueueIndex, prevPPS, prevCPU, "Prev"})
	}
	if nextNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{nexRxQueueIndex, nextPPS, nextCPU, "Next"})
	}

	if len(candidates) > 0 {
		// Scegli quella con minore CPU usage
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.cpu < best.cpu {
				best = c
			}
		}
		p.Printf("%s RXQueue %d is best (CPU=%f) by (CPU=%f) \n", best.name, listRxQueue[best.rxQueueIndex], best.cpu, oldCPU-best.cpu)
		// p.Printf("%s RXQueue %d is best (CPU=%f) (PPS=%d) by (CPU=%f) (PPS=%d) \n", best.name, listRxQueue[best.rxQueueIndex], best.cpu, best.pps, oldCPU-best.cpu, int(best.pps)-int(oldPPS))
		config.RXQueue = listRxQueue[best.rxQueueIndex]
		setConfig(ethHandle, config)
		bestPPS = best.pps
		bestCPU = best.cpu
	} else {
		// Nessuna configurazione processa tutto -> massimizza il throughput
		p.Printf("Not all processed, looking for higher throughput\n")
		if float64(prevPPS) > float64(nextPPS)*PPS_THRESHOLD && float64(prevPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(prevPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("Lower RXQueue %d is better by (PPS=%d)\n", listRxQueue[prevRxQueueIndex], prevPPS-oldPPS)
			config.RXQueue = listRxQueue[prevRxQueueIndex]
			bestPPS = prevPPS
			bestCPU = prevCPU
		} else if float64(nextPPS) > float64(prevPPS)*PPS_THRESHOLD && float64(nextPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(nextPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("Higher RXQueue %d is better by (PPS=%d)\n", listRxQueue[nexRxQueueIndex], nextPPS-oldPPS)
			config.RXQueue = listRxQueue[nexRxQueueIndex]
			bestPPS = nextPPS
			bestCPU = nextCPU
		} else {
			p.Printf("Current RXQueue %d is better\n", listRxQueue[oldRxQueueIndex])
			config.RXQueue = listRxQueue[oldRxQueueIndex]
			bestPPS = oldPPS
			bestCPU = oldCPU
		}
		setConfig(ethHandle, config)
	}

	return config, bestPPS, bestCPU

}

/*
test and update the current RX budget size if there is a gain in throughput
*/
func changeRxBudget(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64, float64) {
	var listBudget = []uint32{2, 4, 8, 16, 32, 64, 128, 256, 512}

	oldPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	oldCPU := getAverageCPUPercentage(config.Weight)
	oldNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)

	var nextPPS uint64
	var nextCPU float64
	var nextNotProcessed int
	var prevPPS uint64
	var prevCPU float64
	var prevNotProcessed int
	var bestPPS uint64
	var bestCPU float64

	oldBudgetIndex := slices.Index(listBudget, config.Budget)
	prevBudgetIndex := oldBudgetIndex - 1
	nexBudgetIndex := oldBudgetIndex + 1

	//gathers data for the different budget values
	if prevBudgetIndex > 0 {
		config.Budget = listBudget[prevBudgetIndex]
		setConfig(ethHandle, config)
		prevPPS = getAction(ethHandle, config.Iface, interval, config.Action)
		prevCPU = getAverageCPUPercentage(config.Weight)
		prevNotProcessed = getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	}
	if nexBudgetIndex < len(listBudget) {
		config.Budget = listBudget[nexBudgetIndex]
		setConfig(ethHandle, config)
		nextPPS = getAction(ethHandle, config.Iface, interval, config.Action)
		nextCPU = getAverageCPUPercentage(config.Weight)
		nextNotProcessed = getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	}
	p := message.NewPrinter(language.English)
	// fmt.Printf("Old %d, Next %d, Prev %d, extern %d\n", old, next, prev, extDrop)

	type candidate struct {
		budgetIndex int
		pps         uint64
		cpu         float64
		name        string
	}
	var candidates []candidate
	// Raccogli solo le configurazioni che processano tutto
	if oldNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{oldBudgetIndex, oldPPS, oldCPU, "Old"})
	}
	if prevNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{prevBudgetIndex, prevPPS, prevCPU, "Prev"})
	}
	if nextNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{nexBudgetIndex, nextPPS, nextCPU, "Next"})
	}
	if len(candidates) > 0 {
		// Scegli quella con minore CPU usage
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.cpu < best.cpu {
				best = c
			}
		}
		p.Printf("%s Budget %d is best (CPU=%f) by (CPU=%f) \n", best.name, listBudget[best.budgetIndex], best.cpu, oldCPU-best.cpu)
		// p.Printf("%s Budget %d is best (CPU=%f) (PPS=%d) by (CPU=%f) (PPS=%d) \n", best.name, listBudget[best.budgetIndex], best.cpu, best.pps, oldCPU-best.cpu, int(best.pps)-int(oldPPS))
		config.Budget = listBudget[best.budgetIndex]
		setConfig(ethHandle, config)
		bestPPS = best.pps
		bestCPU = best.cpu
	} else {
		// Nessuna configurazione processa tutto -> massimizza il throughput
		p.Printf("Not all processed, looking for higher throughput\n")
		if float64(prevPPS) > float64(nextPPS)*PPS_THRESHOLD && float64(prevPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(prevPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("Lower Budget %d is better by (PPS=%d)\n", listBudget[prevBudgetIndex], prevPPS-oldPPS)
			config.Budget = listBudget[prevBudgetIndex]
			bestPPS = prevPPS
			bestCPU = prevCPU
		} else if float64(nextPPS) > float64(prevPPS)*PPS_THRESHOLD && float64(nextPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(nextPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("Higher Budget %d is better by (PPS=%d)\n", listBudget[nexBudgetIndex], nextPPS-oldPPS)
			config.Budget = listBudget[nexBudgetIndex]
			bestPPS = nextPPS
			bestCPU = nextCPU
		} else {
			p.Printf("Current Budget %d is better\n", listBudget[oldBudgetIndex])
			config.Budget = listBudget[oldBudgetIndex]
			bestPPS = oldPPS
			bestCPU = oldCPU
		}
		setConfig(ethHandle, config)
	}
	return config, bestPPS, bestCPU
}

func changeCqeCompress(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64, float64) {

	oldPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	oldCPU := getAverageCPUPercentage(config.Weight)
	oldNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)

	oldCQECompress := config.CQECompress
	newCQECompress := !oldCQECompress

	var bestPPS uint64
	var bestCPU float64

	config.CQECompress = newCQECompress
	setConfig(ethHandle, config)

	newPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	newCPU := getAverageCPUPercentage(config.Weight)
	newNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	p := message.NewPrinter(language.English)

	type candidate struct {
		cqeCompress bool
		pps         uint64
		cpu         float64
		name        string
	}

	var candidates []candidate

	// Considera solo quelle che processano tutto
	if oldNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{oldCQECompress, oldPPS, oldCPU, "Old"})
	}
	if newNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{newCQECompress, newPPS, newCPU, "New"})
	}

	if len(candidates) > 0 {
		// Tra quelle valide, scegli la meno pesante in termini di CPU
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.cpu < best.cpu {
				best = c
			}
		}
		p.Printf("%s CQE Compression %t is best (CPU=%f) by (CPU=%f)\n", best.name, best.cqeCompress, best.cpu, oldCPU-best.cpu)
		config.CQECompress = best.cqeCompress
		setConfig(ethHandle, config)
		bestPPS = best.pps
		bestCPU = best.cpu
	} else {
		// Nessuna delle due processa tutto → massimizza il throughput
		p.Printf("Not all processed, looking for higher throughput\n")
		if float64(newPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(newPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("New CQE Compression %t is better by (PPS=%d)\n", newCQECompress, newPPS-oldPPS)
			config.CQECompress = newCQECompress
			bestPPS = newPPS
			bestCPU = newCPU
		} else {
			p.Printf("Previous CQE Compression %t was better by (PPS=%d), reverting\n", oldCQECompress, oldPPS-newPPS)
			config.CQECompress = oldCQECompress
			bestPPS = oldPPS
			bestCPU = oldCPU
		}
		setConfig(ethHandle, config)
	}
	return config, bestPPS, bestCPU
}

func changeRxStriding(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64, float64) {

	oldPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	oldCPU := getAverageCPUPercentage(config.Weight)
	oldNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)

	oldRxStriding := config.Striding
	newRxStriding := !oldRxStriding
	var bestPPS uint64
	var bestCPU float64

	config.Striding = newRxStriding
	setConfig(ethHandle, config)

	newPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	newCPU := getAverageCPUPercentage(config.Weight)
	newNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	p := message.NewPrinter(language.English)
	type candidate struct {
		rxStriding bool
		pps        uint64
		cpu        float64
		name       string
	}

	var candidates []candidate

	// Considera solo le configurazioni che processano tutto
	if oldNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{oldRxStriding, oldPPS, oldCPU, "Old"})
	}
	if newNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{newRxStriding, newPPS, newCPU, "New"})
	}

	if len(candidates) > 0 {
		// Tra le valide, scegli quella con minore utilizzo CPU
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.cpu < best.cpu {
				best = c
			}
		}
		p.Printf("%s Rx Striding %t is best (CPU=%f) by (CPU=%f)\n", best.name, best.rxStriding, best.cpu, oldCPU-best.cpu)
		config.Striding = best.rxStriding
		setConfig(ethHandle, config)
		bestPPS = best.pps
		bestCPU = best.cpu
	} else {
		// Nessuna processa tutto → confronto throughput
		p.Printf("Not all processed, looking for higher throughput\n")
		if float64(newPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(newPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("New Rx Striding %t is better by (PPS=%d)\n", newRxStriding, newPPS-oldPPS)
			config.Striding = newRxStriding
			bestPPS = newPPS
			bestCPU = newCPU
		} else {
			p.Printf("Previous Rx Striding %t was better by (PPS=%d), reverting\n", oldRxStriding, oldPPS-newPPS)
			config.Striding = oldRxStriding
			bestPPS = oldPPS
			bestCPU = oldCPU
		}
		setConfig(ethHandle, config)
	}

	return config, bestPPS, bestCPU
}

func changeWRMSR(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64, float64) {

	oldPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	oldCPU := getAverageCPUPercentage(config.Weight)
	oldNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)

	var bestPPS uint64
	var bestCPU float64
	var newMSRval uint64
	oldMSRval := config.MSRValue

	if oldMSRval == 0x6000 {
		newMSRval = 0x7fff
	} else {
		newMSRval = 0x6000
	}

	setMSR(newMSRval)

	newPPS := getAction(ethHandle, config.Iface, interval, config.Action)
	newCPU := getAverageCPUPercentage(config.Weight)
	newNotProcessed := getNotProcessed(ethHandle, config.Iface, interval, config.Action)
	p := message.NewPrinter(language.English)

	type candidate struct {
		msrValue uint64
		pps      uint64
		cpu      float64
		name     string
	}

	var candidates []candidate

	// Considera solo le configurazioni che processano tutto
	if oldNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{oldMSRval, oldPPS, oldCPU, "Old"})
	}
	if newNotProcessed < DROPPED_THRESHOLD {
		candidates = append(candidates, candidate{newMSRval, newPPS, newCPU, "New"})
	}

	if len(candidates) > 0 {
		// Tra quelle valide, scegli la meno pesante in termini di CPU
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.cpu < best.cpu {
				best = c
			}
		}
		p.Printf("%s MSR %x is best (CPU=%f) by (CPU=%f)\n", best.name, best.msrValue, best.cpu, oldCPU-best.cpu)
		config.MSRValue = best.msrValue
		setMSR(best.msrValue)
		bestPPS = best.pps
		bestCPU = best.cpu
	} else {
		// Nessuna configurazione è completa → confronta il throughput
		p.Printf("Not all processed, looking for higher throughput\n")
		if float64(newPPS) > float64(oldPPS)*PPS_THRESHOLD && float64(newPPS) > float64(extDrop)*PPS_THRESHOLD {
			p.Printf("New MSR %x is better by (PPS=%d)\n", newMSRval, newPPS-oldPPS)
			config.MSRValue = newMSRval
			setMSR(newMSRval)
			bestPPS = newPPS
			bestCPU = newCPU
		} else {
			p.Printf("Previous MSR %x was better by (PPS=%d), reverting\n", oldMSRval, oldPPS-newPPS)
			config.MSRValue = oldMSRval
			setMSR(oldMSRval)
			bestPPS = oldPPS
			bestCPU = oldCPU
		}
	}

	return config, bestPPS, bestCPU

}

func createSlice(ones uint32, start uint32) [MAX_CORES]uint32 {
	var slice [MAX_CORES]uint32
	for i := start; i < ones; i++ {
		slice[i] = 1
	}
	return slice
}

func changeCPUCount(ethHandle *ethtool.Ethtool, config Config, interval int, extDrop uint64) (Config, uint64) {

	oldWeight := config.Weight
	oldCore := config.Cores
	var maxDrop uint64

	percentage := getAverageCPUPercentage(config.Weight)
	if percentage > 80 && config.Cores < MAX_CORES {

		config.Weight = createSlice(config.Cores+1, 0)
		config.Cores++

	} else if percentage < 60 && config.Cores > 1 {

		percentages, err := cpu.Percent(time.Second, true)
		percentages = percentages[:config.Cores-1]

		if err != nil {
			panic(err.Error())
		}
		maxPercent := slices.Max(percentages)
		maxIndex := slices.Index(percentages, maxPercent)
		minPercent := slices.Min(percentages)
		minIndex := slices.Index(percentages, minPercent)
		//traffic skewed
		if maxPercent > 80 && minPercent < 60 {
			fmt.Printf("CPU %d is max\n", maxIndex)
			fmt.Printf("CPU %d is min\n", minIndex)
			fmt.Printf("percentages %v\n", percentages)
			equalizeIndir(ethHandle, config, uint32(minIndex), uint32(maxIndex))
			//test
			return config, extDrop
		}

		config.Weight = createSlice(config.Cores-1, 0)
		config.Cores--

	}

	setIndir(ethHandle, config)

	new := getAction(ethHandle, config.Iface, interval, config.Action)

	if float64(new) > float64(extDrop)*PPS_THRESHOLD {
		fmt.Printf("New CPU %d more than prevoius\n", config.Cores)
		maxDrop = new
	} else {
		fmt.Printf("Prevous CPU %d less than prevoius reverting\n", oldCore)
		config.Cores = oldCore
		config.Weight = oldWeight
		setIndir(ethHandle, config)
		maxDrop = extDrop
	}

	// maxDrop = new

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
		Action:      "rx_xdp_drop",
		Budget:      64,
		RXQueue:     1024,
		CQECompress: true,
		Striding:    true,
		Weight:      [32]uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		Cores:       10,
		MSR:         0xc8b,
		MSRValue:    0x6000,
	}
	setConfig(ethHandle, config)
	setIndir(ethHandle, config)
	setMSR(config.MSRValue)

	// prova := ethtool.SetIndir{}
	// newIndir := [256]uint32{0}
	// newIndir[0] = 1
	// prova.RingIndex = newIndir
	// overrideIndir(ethHandle, config.Iface, prova)

	// getAverageCPUPercentage(config.Weight)
	// return

	var pps uint64
	var cpuUsage float64

	xdpLink := attachXDP(config.Iface)
	defer xdpLink.Close()

	//baseline
	pps = getAction(ethHandle, config.Iface, INTERVAL, config.Action)
	writeCSV(writer, config, pps, getAverageCPUPercentage(config.Weight))

	// config.RXQueue = 128
	// config.Budget = 2
	// config.CQECompress = false
	// config.Striding = false
	// setConfig(ethHandle, config)

	for {
		pps = 0

		config, pps, cpuUsage = changeRxQueue(ethHandle, config, INTERVAL, pps)
		writeCSV(writer, config, pps, cpuUsage)

		config, pps, cpuUsage = changeRxBudget(ethHandle, config, INTERVAL, pps)
		writeCSV(writer, config, pps, cpuUsage)

		config, pps, cpuUsage = changeCqeCompress(ethHandle, config, INTERVAL, pps)
		writeCSV(writer, config, pps, cpuUsage)

		config, pps, cpuUsage = changeRxStriding(ethHandle, config, INTERVAL, pps)
		writeCSV(writer, config, pps, cpuUsage)

		// config, pps, cpuUsage = changeCPUCount(ethHandle, config, INTERVAL, pps)
		// writeCSV(writer, config, pps, cpuUsage)

		config, pps, cpuUsage = changeWRMSR(ethHandle, config, INTERVAL, pps)
		writeCSV(writer, config, pps, cpuUsage)

	}

}
