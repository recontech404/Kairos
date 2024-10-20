package extractors

import (
	"strings"
	"sync"

	"github.com/google/uuid"
)

var malwarePids = make(map[uint32]bool)
var malPidMutex = &sync.Mutex{}

func addPidToFilter(pid uint32) {
	malPidMutex.Lock()
	malwarePids[pid] = true
	malPidMutex.Unlock()
}

func removePidToFilter(pid uint32) {
	malPidMutex.Lock()
	if _, ok := malwarePids[pid]; ok {
		delete(malwarePids, pid)
	}
	malPidMutex.Unlock()
}

func checkPidIsFiltered(pid uint32) bool {
	malPidMutex.Lock()
	defer malPidMutex.Unlock()
	if _, ok := malwarePids[pid]; ok {
		return true
	}
	return false
}

// -------> job done channel fanout controller <------
var jobDoneListners = 0
var jobDLMu = &sync.Mutex{}

func addJobDoneListener() {
	jobDLMu.Lock()
	jobDoneListners++
	jobDLMu.Unlock()
}

func getJobDoneListenerCount() int {
	jobDLMu.Lock()
	defer jobDLMu.Unlock()
	return jobDoneListners
}

// -------> run command pid managment <--------
var benignPids = make(map[uint32]bool)
var benignPidMu = &sync.Mutex{}

func addBenignPid(pid uint32) {
	benignPidMu.Lock()
	benignPids[pid] = true
	benignPidMu.Unlock()
}

func checkPidIsBenign(pid uint32) bool {
	benignPidMu.Lock()
	defer benignPidMu.Unlock()
	if _, ok := benignPids[pid]; ok {
		return true
	}
	return false
}

/*
execvePidFilterCheck is called every time a execve syscall is detected.
EPFC will check if the parent pid is benign (known but not monitored).
If the ppid is known *and* the filepath (bin path) is not user excluded,
it will add the new execve pid as a malicious pid to monitor.
*/
func execvePidFilterCheck(pid, ppid uint32, binPath string, addPidChan chan<- uint32) {
	if checkPidIsBenign(ppid) {
		if len(getGlobalBinExclusions()) > 0 {
			for _, exl := range getGlobalBinExclusions() {
				if !strings.Contains(binPath, exl) {
					addPidToFilter(pid)
					addPidChan <- pid //always add pid to ssl map if it is related
					break
				} else {
					addBenignPid(pid)
					addPidChan <- pid
				}
			}
		} else {
			addPidToFilter(pid)
			addPidChan <- pid
		}

	}
}

// -------> jobID management <----------

var globalJobID = uuid.Nil
var jobIDMutex = &sync.Mutex{}

var runningJobBool = false
var receivedJobMu = &sync.Mutex{}

var globalBinExclusions []string
var globalBinExclusionsMu = &sync.Mutex{}

var runCommandSyscallEL = false
var runCommandSyscallELMu = &sync.Mutex{}

func setGlobalJobID(id uuid.UUID) {
	jobIDMutex.Lock()
	globalJobID = id
	jobIDMutex.Unlock()
}

func getGlobalJobID() uuid.UUID {
	jobIDMutex.Lock()
	defer jobIDMutex.Unlock()
	return globalJobID
}

func setRunningJobTrue() {
	receivedJobMu.Lock()
	runningJobBool = true
	receivedJobMu.Unlock()
}

func runningJob() bool {
	receivedJobMu.Lock()
	defer receivedJobMu.Unlock()
	return runningJobBool
}

func setGlobalBinExclusions(exclusions []string) {
	globalBinExclusionsMu.Lock()
	globalBinExclusions = exclusions
	globalBinExclusionsMu.Unlock()
}

func getGlobalBinExclusions() []string {
	globalBinExclusionsMu.Lock()
	defer globalBinExclusionsMu.Unlock()
	return globalBinExclusions
}

func setRunCommandSyscallELTrue() {
	runCommandSyscallELMu.Lock()
	runCommandSyscallEL = true
	runCommandSyscallELMu.Unlock()
}

func getRunCommandSyscallEL() bool {
	runCommandSyscallELMu.Lock()
	defer runCommandSyscallELMu.Unlock()
	return runCommandSyscallEL
}
