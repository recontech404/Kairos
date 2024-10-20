//go:build !darwin

package extractors

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"kairos-runner/adapters"
	"kairos-runner/types"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	log "github.com/sirupsen/logrus"
)

const (
	eBPFObject      = "eBPF/main.bpf.o"
	readDataBuffErr = "unable to read data buffer: "
)

func StarteBPFCaptures(ctx context.Context, ws *adapters.WSHandler, verboseLog bool, jobDone <-chan struct{}, allSendDone chan<- struct{}) {
	// disables libbpf stdout logging
	callback := bpf.Callbacks{
		LogFilters: []func(libLevel int, msg string) bool{},
		Log:        func(level int, msg string) {},
	}
	bpf.SetLoggerCbs(callback)

	bpfModule, err := bpf.NewModuleFromFile(eBPFObject)
	if err != nil {
		log.Fatalf("unable to find ebpf object: %v", err)
	}
	if err := resizeMap(bpfModule, sslMapName, 4096*64); err != nil { // ssl map
		log.Fatalf("unable to resize ebpf ssl map: %v", err)
	}
	if err := resizeMap(bpfModule, mapName, 8192*64); err != nil { // tracepoint map
		log.Fatalf("unable to resize tracepoint map: %v", err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalf("unable to load ebpf object: %v", err)
	}

	//************** Tracepoints ************//
	eBPFEventChan := make(chan []byte)
	defer close(eBPFEventChan)

	bpfModule, err = setupeBPFProgramTracepoints(bpfModule)
	if err != nil {
		log.Fatalf("unable to setup ebpf tracepoint programs: %v", err)
	}

	rbT, err := bpfModule.InitRingBuf(mapName, eBPFEventChan)
	if err != nil {
		log.Fatalf("unable to init ring buf: %v", err)
	}

	rbT.Poll(50)
	defer func() {
		rbT.Stop()
		rbT.Close()
	}()

	//************* Uprobes **************//
	ebpfSSLEventChan := make(chan []byte)
	defer close(ebpfSSLEventChan)

	bpfModule, err = setupEBPFCryptCapture(bpfModule)
	if err != nil {
		log.Fatalf("unable to setup epbf ssl uprobes: %v", err)
	}

	rbS, err := bpfModule.InitRingBuf(sslMapName, ebpfSSLEventChan)
	if err != nil {
		log.Fatalf("unable to init ssl ring buf: %v", err)
	}

	rbS.Poll(100)
	defer func() {
		rbS.Stop()
		rbS.Close()
	}()

	sendEventChan := make(chan []byte)
	defer close(sendEventChan)

	c2EventChan := make(chan singleC2)
	defer close(c2EventChan)

	sslEventChan := make(chan singleSSL)
	defer close(sslEventChan)

	addSenderChan := make(chan struct{})
	defer close(addSenderChan)

	senderDoneChan := make(chan struct{})
	defer close(senderDoneChan)

	go manageProcessSendStatus(ctx, ws, addSenderChan, senderDoneChan, allSendDone)

	setupMainProcessEventSender(ctx, ws, sendEventChan, jobDone, senderDoneChan)

	setupMetaEventSender(ctx, ws, c2EventChan, sslEventChan, jobDone, senderDoneChan)
	addSenderChan <- struct{}{}

	defer close(ws.AddPidChan)

	go startPidMapFilterController(ctx, bpfModule, ws.AddPidChan)

	for {
		select {
		case e := <-eBPFEventChan:
			go func() {
				err := processTracepointEvent(verboseLog, e, sendEventChan, c2EventChan, ws.AddPidChan)
				if err != nil {
					log.Errorf("error processing tracepoint: %v", err) //try to continue instead of returning
				}
			}()
		case e := <-ebpfSSLEventChan:
			go func() {
				if err := processSSLEvent(e, sslEventChan); err != nil {
					log.Errorf("error processing ssl event: %v", err) //try to continue instead of returning
				}
			}()
		case <-ctx.Done():
			break
		}
	}

}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}
	if err = m.SetMaxEntries(size); err != nil {
		return err
	}
	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}

func startPidMapFilterController(ctx context.Context, bpf *bpf.Module, pid <-chan uint32) {
	pidMap, err := bpf.GetMap("pid_map")
	if err != nil {
		log.Fatalf("unable to load pid map: %v", err)
	}

	for {
		select {
		case pid := <-pid:
			if err := pidMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&pid)); err != nil {
				log.Warnf("unable to add pid: %d to map: %v", pid, err)
			}
		case <-ctx.Done():
			break
		}
	}
}

func manageProcessSendStatus(ctx context.Context, ws *adapters.WSHandler, addSender <-chan struct{}, senderDone <-chan struct{}, allSendersDone chan<- struct{}) {
	var wg sync.WaitGroup
	breakListen := make(chan struct{})

	wg.Add(1) //main job sender

	go func() {
		wg.Wait()
		informServerDoneSending(ctx, ws)
		allSendersDone <- struct{}{}
		breakListen <- struct{}{}
		close(breakListen)
		return
	}()

listen:
	for {
		select {
		case <-addSender:
			wg.Add(1)
		case <-senderDone:
			wg.Done()
		case <-breakListen:
			break listen
		case <-ctx.Done():
			log.Warn("manage process sender states context cancelled before all senders finished")
			break listen
		}
	}
}

func informServerDoneSending(ctx context.Context, ws *adapters.WSHandler) {
	runnerDoneSending := types.RunnerJIDM{
		JobID: getGlobalJobID(),
	}

	rDSMsg, err := adapters.WSMarshalObject(runnerDoneSending, types.RunnerDoneSendingMsg)
	if err != nil {
		log.Errorf("unable to marshal runner done sending msg: %v", err)
		return
	}
	err = ws.SendMessage(ctx, rDSMsg)
	if err != nil {
		log.Errorf("unable to send runner done sending msg: %v", err)
	}
	log.Info("Sent Done Sending Msg")
}

func setupMainProcessEventSender(ctx context.Context, ws *adapters.WSHandler, sendEventChan <-chan []byte, jobDone <-chan struct{}, senderDone chan<- struct{}) {
	buffer := new(bytes.Buffer)
	sync := &sync.Mutex{}

	addJobDoneListener() //adding listener

	go func() {
		for {
			select {
			case event := <-sendEventChan:
				sync.Lock()
				buffer.Write(event)
				sync.Unlock()
			case <-jobDone:
				var rawJobData = types.JobData{
					JobID:   getGlobalJobID(),
					RawData: buffer.Bytes(),
				}
				jobDataMsg, err := adapters.WSMarshalObject(rawJobData, types.JobDataMsg)
				if err != nil {
					log.Errorf("failure to marshal main process data: %v", err)
					return
				}

				err = ws.SendMessage(ctx, jobDataMsg)
				if err != nil {
					log.Errorf("failure sending main process data: %v", err) //TODO determine if log.fatal is better
					return
				}
				log.Info("Sent Main Job Data")
				senderDone <- struct{}{} //for main proc
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func setupMetaEventSender(ctx context.Context, ws *adapters.WSHandler, c2EventChan <-chan singleC2, sslEventChan <-chan singleSSL, jobDone <-chan struct{}, senderDone chan<- struct{}) {
	c2Map := make(map[string]int)
	c2sync := &sync.Mutex{}

	sslMap := make(map[int]string)
	sslSync := &sync.Mutex{}

	addJobDoneListener()

	go func() {
		for {
			select {
			case event := <-c2EventChan:
				c2sync.Lock()
				c2Map[event.ip] = event.port
				c2sync.Unlock()
			case event := <-sslEventChan:
				sslSync.Lock()
				if existingData, exists := sslMap[event.threadID]; exists {
					sslMap[event.threadID] = existingData + event.data
				} else {
					sslMap[event.threadID] = event.data
				}
				sslSync.Unlock()
			case <-jobDone:
				var rawC2Data = types.JobMetadata{
					JobID:    getGlobalJobID(),
					C2IPPMap: c2Map,
					SSLMap:   sslMap,
				}
				jobMetadataMsg, err := adapters.WSMarshalObject(rawC2Data, types.JobMetadataMsg)
				if err != nil {
					log.Errorf("failure to marshal job metadata: %v", err)
					return
				}

				err = ws.SendMessage(ctx, jobMetadataMsg)
				if err != nil {
					log.Errorf("failure sending job metadata: %v", err)
					return
				}
				log.Info("Sent Job Metadata")
				senderDone <- struct{}{}
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func readBinaryDataBuffer(dataBuffer *bytes.Buffer, dataType interface{}) error {
	return binary.Read(dataBuffer, binary.LittleEndian, dataType)
}

func findLibraryPath(libName, searchPath string) ([]string, error) {
	cmd := exec.Command("find", searchPath, "-name", libName)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return []string{}, fmt.Errorf("unable to find lib: %s", libName)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) > 0 {
		return lines, nil
	}
	return []string{}, fmt.Errorf("unable to find library: %s in path: %s", libName, searchPath)
}
