//go:build !darwin

package extractors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"kairos-runner/types"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	log "github.com/sirupsen/logrus"
)

type singleSSL struct {
	threadID int
	data     string
}

const (
	sslMapName = "ssl_events"
)

func setupEBPFCryptCapture(bpfModule *bpf.Module) (*bpf.Module, error) {
	for lib, programs := range types.EBPFUprobeMap {
		libPaths, err := findLibraryPath(lib, types.SSL_TLS_Base_Path)
		if err != nil {
			return nil, fmt.Errorf("unable to find library for: %s err: %v", lib, err)
		}
		for _, libPath := range libPaths {
			if libPath == "" {
				log.Warnf("Unable to find library for: %s skipping uprobes", lib)
				continue
			}
			for progToUprobe, offsetSymbol := range programs {
				offset, err := helpers.SymbolToOffset(libPath, offsetSymbol)
				if err != nil {
					return nil, fmt.Errorf("unable to find offset for: %s err: %v", progToUprobe, err)
				}

				prog, err := bpfModule.GetProgram(progToUprobe)
				if err != nil {
					return nil, fmt.Errorf("unable to find ebpf program for uprobe: %s err: %v", progToUprobe, err)
				}

				if _, err = prog.AttachUprobe(-1, libPath, offset); err != nil {
					return nil, fmt.Errorf("unable to attach uprobe: %v", err)
				}
			}
		}
	}

	for lib, programs := range types.EBPFUretprobeMap {
		libPaths, err := findLibraryPath(lib, types.SSL_TLS_Base_Path)
		if err != nil {
			return nil, fmt.Errorf("unable to find library for: %s err: %v", lib, err)
		}
		for _, libPath := range libPaths {
			if libPath == "" {
				log.Warnf("Unable to find library for: %s skipping uretprobes", lib)
				continue
			}
			for progToUprobe, offsetSymbol := range programs {
				offset, err := helpers.SymbolToOffset(libPath, offsetSymbol)
				if err != nil {
					return nil, fmt.Errorf("unable to find offset for: %s err: %v", progToUprobe, err)
				}

				prog, err := bpfModule.GetProgram(progToUprobe)
				if err != nil {
					return nil, fmt.Errorf("unable to find ebpf program for upretrobe: %s err: %v", progToUprobe, err)
				}

				if _, err = prog.AttachURetprobe(-1, libPath, offset); err != nil {
					return nil, fmt.Errorf("unable to attach uretprobe: %v", err)
				}
			}
		}
	}

	return bpfModule, nil
}

func processSSLEvent(rawEvent []byte, sslEventChan chan<- singleSSL) error {
	var checkType types.CheckParamType
	var dataBuffer *bytes.Buffer

	dataBuffer = bytes.NewBuffer(rawEvent)
	err := binary.Read(dataBuffer, binary.LittleEndian, &checkType)
	if err != nil {
		return fmt.Errorf("unable to read rawEvent: %v", err)
	}

	if checkPidIsFiltered(checkType.Pid) || checkPidIsBenign(checkType.Pid) { //capture all ssl events related to malware
		if event, ok := types.NumberToSSLHeaderMap[int(checkType.ParamType)]; ok {
			if err := extractSSLEvent(dataBuffer, sslEventChan, event); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractSSLEvent(dataBuffer *bytes.Buffer, sslEventChan chan<- singleSSL, eventType string) error {
	var data types.SSLData
	if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
		return fmt.Errorf(readDataBuffErr, err)
	}
	sslEvent := singleSSL{
		threadID: int(data.Tid),
	}
	sslEvent.data = fmt.Sprintf("%s: %s\n", eventType, data.Data)
	//log.Info(sslEvent.data) //uncomment for more debug info
	sslEventChan <- sslEvent

	return nil
}
