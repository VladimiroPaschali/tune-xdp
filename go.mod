module main

go 1.24.1

require golang.org/x/text v0.23.0

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
)

require (
	github.com/cilium/ebpf v0.17.3
	github.com/shirou/gopsutil/v3 v3.24.5
	golang.org/x/sys v0.30.0 // indirect
)

require github.com/VladimiroPaschali/ethtool-indir v0.0.0

replace github.com/VladimiroPaschali/ethtool-indir => ../ethtool-indir
