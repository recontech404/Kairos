//go:build !darwin

package extractors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"kairos-runner/types"
	"net"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
	log "github.com/sirupsen/logrus"
)

type singleC2 struct {
	ip   string
	port int
}

const (
	eBPFSysCategory = "syscalls"
	eBPFNetCategory = "net"
	mapName         = "events"
)

func setupeBPFProgramTracepoints(bpfModule *bpf.Module) (*bpf.Module, error) {
	for program, tracepoint := range types.EBPFProgramToTracepoint {
		prog, err := bpfModule.GetProgram(program)
		if err != nil {
			return nil, fmt.Errorf("unable to get ebpf program: %s err:%v", program, err)
		}
		if _, err := prog.AttachTracepoint(eBPFSysCategory, tracepoint); err != nil {
			return nil, fmt.Errorf("unable to attach tracepoint: %s error: %v", tracepoint, err)
		}
	}

	//DNS program in net tracepoint
	prog, err := bpfModule.GetProgram(types.Handle_dns)
	if err != nil {
		return nil, fmt.Errorf("dns err: %v", err)
	}
	if _, err := prog.AttachTracepoint(eBPFNetCategory, types.Net_dev_queue); err != nil {
		return nil, fmt.Errorf("attach dns err: %v", err)
	}
	return bpfModule, nil
}

func processTracepointEvent(verboseLog bool, rawEvent []byte, sendEventChan chan<- []byte, c2EventChan chan<- singleC2, addPidChan chan<- uint32) error {
	var checkType types.CheckParamType
	var dataBuffer *bytes.Buffer

	dataBuffer = bytes.NewBuffer(rawEvent)
	err := binary.Read(dataBuffer, binary.LittleEndian, &checkType)
	if err != nil {
		return fmt.Errorf("unable to read rawEvent: %v", err)
	}

	if checkType.ParamType == 7 { //check all execve events for related processes
		copyBuff := bytes.NewBuffer(make([]byte, 0, dataBuffer.Len()))
		copyBuff.Write(dataBuffer.Bytes())

		err := checkNewExecveEvent(copyBuff, checkType.Pid, checkType.PPid, addPidChan)
		if err != nil {
			return err
		}
	}

	if checkPidIsFiltered(checkType.Pid) {
		if event, ok := types.NumberToSysMap[int(checkType.ParamType)]; ok {
			if event == types.Sys_enter_read && getRunCommandSyscallEL() { //we skip read events as they produce too much noise for the LLM when running command
				return nil
			}
			formattedEvent, err := extractFormatSysEvent(event, dataBuffer, c2EventChan)
			if err != nil {
				return err
			}
			if formattedEvent != nil {
				sendEventChan <- formattedEvent
				if verboseLog {
					log.Info(string(formattedEvent))
				}
			}
		}
	}
	return nil
}

func checkNewExecveEvent(dataBuffer *bytes.Buffer, pid, ppid uint32, addPidChan chan<- uint32) error {
	var data types.ExecveData
	if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
		return fmt.Errorf("unable to check execve event: %v - %v", readDataBuffErr, err)
	}
	execvePidFilterCheck(pid, ppid, formatPrint(data.Filename), addPidChan)
	return nil
}

func extractFormatSysEvent(eventType string, dataBuffer *bytes.Buffer, c2EventChan chan<- singleC2) ([]byte, error) {
	outputString := "%s\t %s\t %s\n" //func name - func args - return val
	switch eventType {
	case types.Sys_enter_mkdir:
		var data types.MkdirData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "mkdir", data.Pathname, "")

	case types.Sys_enter_openat:
		var data types.OpenatData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "open", fmt.Sprintf("filepath: %s  flags: %d", formatPrint(data.Pathname), data.Flags), "")

	case types.Sys_enter_fork:
		var data types.ForkData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "fork", "", "")

	case types.Sys_enter_prctl:
		var data types.PrctlData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "prctl", fmt.Sprintf("option: %d  arg2: %d  arg3: %d  arg4: %d  arg5: %d", data.Option, data.Arg2, data.Arg3, data.Arg4, data.Arg5), "")

	case types.Sys_enter_getpid:
		var data types.GetpidData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "get_pid", "", "")

	case types.Sys_enter_getppid:
		var data types.GetPPidData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "get_ppid", "", "")

	case types.Sys_enter_execve:
		var data types.ExecveData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "execve", fmt.Sprintf("filename: %s  args: %s  ", formatPrint(data.Filename), fmt.Sprintf("%s", data.Argv[:100])), "")

	case types.Sys_enter_read:
		var data types.ReadData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if len(formatShortPrint(data.Buf)) < 2 { //skip short buffer as no info contained and just creates noise
			return nil, nil
		}
		outputString = fmt.Sprintf(outputString, "read", fmt.Sprintf("fd: %d  buffer: %s  count: %d", data.Fd, formatShortPrint(data.Buf), data.Count), "")

	case types.Sys_enter_readlink:
		var data types.ReadlinkData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "readlink", fmt.Sprintf("path: %s  buffer: %s  bufsiz: %d", formatPrint(data.Path), data.Buf, data.Bufsiz), "")

	case types.Sys_enter_unlink:
		var data types.UnlinkData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "unlink", data.Pathname, "")

	case types.Sys_enter_write:
		var data types.WriteData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if len(formatPrint(data.Buf)) < 4 {
			return nil, nil
		}
		outputString = fmt.Sprintf(outputString, "write", fmt.Sprintf("fd: %d  buffer: %s  count: %d", data.Fd, formatPrint(data.Buf), data.Count), "")

	case types.Sys_enter_renameat:
		var data types.RenameatData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "rename", fmt.Sprintf("old_fd: %d  old_name: %s  new_fd: %d  new_name: %s", data.Olddfd, data.Oldname, data.Newdfd, data.Newname), "")

	case types.Sys_enter_fcntl:
		var data types.FcntlData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "fcntl", fmt.Sprintf("fd: %d  cmd: %d  arg: %d", data.Fd, data.Cmd, data.Arg), "")

	case types.Sys_enter_socket:
		var data types.SocketData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "socket", fmt.Sprintf("family: %d  type: %d  protocol: %d", data.Family, data.Type, data.Protocol), "")

	case types.Sys_enter_getsockopt:
		var data types.GetSockOptData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		outputString = fmt.Sprintf(outputString, "getsockopt", fmt.Sprintf("fd: %d  level: %d  optname: %d  optval: %s  optlen: %d", data.Fd, data.Level, data.Optname, data.Optval, data.Optlen), "")

	case types.Sys_enter_bind:
		var data types.BindData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if data.Port == 0 {
			return nil, nil
		}
		var c2Event singleC2
		if data.IP != 0 {
			ip := convertToIPv4(data.IP)
			outputString = fmt.Sprintf(outputString, "bind", fmt.Sprintf("fd: %d  ip_address:%s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		} else {
			ip := convertToIPv6(data.IP6)
			outputString = fmt.Sprintf(outputString, "bind", fmt.Sprintf("fd: %d  ip_address:%s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		}

	case types.Sys_enter_connect:
		var data types.ConnectData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if data.Port == 0 {
			return nil, nil
		}
		var c2Event singleC2
		if data.IP != 0 {
			ip := convertToIPv4(data.IP)
			outputString = fmt.Sprintf(outputString, "connect", fmt.Sprintf("fd: %d  ip_address: %s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		} else {
			ip := convertToIPv6(data.IP6)
			outputString = fmt.Sprintf(outputString, "connect", fmt.Sprintf("fd: %d  ip_address: %s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		}

	case types.Sys_enter_sendto:
		var data types.SendToData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if data.Port == 0 {
			return nil, nil
		}
		var c2Event singleC2
		if data.IP != 0 {
			ip := convertToIPv4(data.IP)
			outputString = fmt.Sprintf(outputString, "send", fmt.Sprintf("fd: %d ip_address: %s port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		} else {
			ip := convertToIPv6(data.IP6)
			outputString = fmt.Sprintf(outputString, "send", fmt.Sprintf("fd: %d  ip_address: %s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		}

	case types.Sys_enter_recvfrom:
		var data types.RecvFromData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		if data.Port == 0 {
			return nil, nil
		}
		var c2Event singleC2
		if data.IP != 0 {
			ip := convertToIPv4(data.IP)
			outputString = fmt.Sprintf(outputString, "receive", fmt.Sprintf("fd: %d ip_address: %s port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		} else {
			ip := convertToIPv6(data.IP6)
			outputString = fmt.Sprintf(outputString, "receive", fmt.Sprintf("fd: %d  ip_address: %s  port: %d", data.Fd, ip, data.Port), "")
			c2Event.ip = ip
			c2Event.port = int(data.Port)
			c2EventChan <- c2Event
		}
	case types.Net_dev_queue:
		var data types.DNSData
		if err := readBinaryDataBuffer(dataBuffer, &data); err != nil {
			return nil, fmt.Errorf(readDataBuffErr, err)
		}
		domain := dnsPrint(data.Domain)
		outputString = fmt.Sprintf(outputString, "dns", fmt.Sprintf("domain: %s len: %d", domain, data.Len), "")
		var c2Event singleC2
		c2Event.ip = domain
		c2Event.port = 53
		c2EventChan <- c2Event

	}
	return []byte(outputString), nil
}

func dnsPrint(b [256]byte) string {
	str := string(b[:])
	str = strings.Trim(str, "\000") //remove null characters

	if strings.HasPrefix(str, ".") {
		str = str[1:]
	}

	if strings.HasSuffix(str, ".") {
		str = str[:len(str)-1]
	}

	return str
}

func formatPrint(b [256]byte) string {
	return strings.ReplaceAll(string(bytes.Split(b[:], []byte("\x00"))[0]), "\n", "")
}

func formatShortPrint(b [256]byte) string {
	return strings.ReplaceAll(string(bytes.Split(b[:60], []byte("\x00"))[0]), "\n", "")
}

func convertToIPv4(ipInt uint32) string {
	ip := make([]byte, 4)
	ip[0] = byte(ipInt)
	ip[1] = byte(ipInt >> 8)
	ip[2] = byte(ipInt >> 16)
	ip[3] = byte(ipInt >> 24)
	return net.IP(ip).String()
}

func convertToIPv6(ipChar [16]byte) string {
	return net.IP(ipChar[:]).String()
}
