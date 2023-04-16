package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/shirou/gopsutil/v3/host"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -g -Werror -D __TARGET_ARCH_x86" -type event bpf runqslower.bpf.c

var (
	bootTimeSec uint64
)

func main() {

	// Load pre-compiled programs into the kernel.
	bpfObjs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("lad object: %s", err)
	}
	// bpfObject中の定数を書き換え
	consts := map[string]interface{}{
		"targ_pid":  uint32(0), // pid_t 型のサイズ
		"min_us":    uint64(10000),
		"targ_tgid": uint32(0),
	}
	if err := spec.RewriteConstants(consts); err != nil {
		log.Fatalf("error RewriteConstants: %s", err)
	}
	if err := spec.LoadAndAssign(&bpfObjs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("load and asign object: %s", err)
	}

	defer bpfObjs.Close()

	// BPF Programのアタッチ
	tp1, err := link.AttachTracing(link.TracingOptions{Program: bpfObjs.SchedWakeup})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer tp1.Close()
	tp2, err := link.AttachTracing(link.TracingOptions{Program: bpfObjs.SchedWakeupNew})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer tp2.Close()
	tp3, err := link.AttachTracing(link.TracingOptions{Program: bpfObjs.SchedSwitch})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer tp3.Close()

	// perf event readerをオープンする
	rd, err := perf.NewReader(bpfObjs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening perf event reader: %s", err)
	}
	defer rd.Close()

	// CTRL+Cを待ち受ける
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-c

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	fmt.Printf("%-32s %-16s %-6s %14s %-16s %-6s\n", "SWITCH_TIME", "COMM", "TID", "LAT(us)", "PREV COMM", "PREV TID")

	// カーネル時刻の変換用
	bootTimeSec, _ = host.BootTime()

	// bpfEvent is generated by bpf2go.
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf(
			"%-32s %-16s %-6d %14d %-16s %-6d\n",
			formatTimestamp(event.SwitchTime),
			unix.ByteSliceToString(event.Task[:]),
			event.Pid,
			event.DeltaUs,
			unix.ByteSliceToString(event.PrevTask[:]),
			event.PrevPid,
		)
	}
}

// カーネルタイムを時刻に変換
func formatTimestamp(ts uint64) string {
	t := time.Unix(int64(bootTimeSec), int64(ts))
	return t.Format(time.RFC3339Nano)
}
