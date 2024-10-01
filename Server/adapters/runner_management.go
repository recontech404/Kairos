package adapters

import (
	"kairos-server/types"
	"sync"
)

type (
	RunnerManagment struct {
		count           int
		runnerMap       map[websocketID]*types.RunnerData
		rmMu            *sync.Mutex
		runnersReadyMap map[websocketID]string //stores the runners which are available for jobs and the arch they support
		rrMu            *sync.Mutex
	}

	RMI interface {
		addRunner(websocketID, types.RunnerData)
		getRunner(websocketID) *types.RunnerData
		getAllRunners() *[]types.RunnerData
		getRunnerCount() int
		deleteRunner(websocketID)
		checkInRunner(websocketID, string)
		checkOutRunner(string) (websocketID, bool)
		manualDeleteRunnerReady(websocketID)
	}
)

func SetupRunnerManager() RMI {
	return &RunnerManagment{
		count:           0,
		runnerMap:       make(map[websocketID]*types.RunnerData),
		rmMu:            &sync.Mutex{},
		runnersReadyMap: make(map[websocketID]string),
		rrMu:            &sync.Mutex{},
	}
}

func (ro *RunnerManagment) addRunner(id websocketID, runner types.RunnerData) {
	ro.rmMu.Lock()
	ro.count++
	ro.runnerMap[id] = &runner
	ro.rmMu.Unlock()
}

func (ro *RunnerManagment) getRunner(id websocketID) *types.RunnerData {
	ro.rmMu.Lock()
	defer ro.rmMu.Unlock()
	return ro.runnerMap[id]
}

func (ro *RunnerManagment) getAllRunners() *[]types.RunnerData {
	ro.rmMu.Lock()
	var runners []types.RunnerData
	for _, runner := range ro.runnerMap {
		runners = append(runners, *runner)
	}
	ro.rmMu.Unlock()
	return &runners
}

func (ro *RunnerManagment) getRunnerCount() int {
	ro.rmMu.Lock()
	defer ro.rmMu.Unlock()
	return ro.count
}

func (ro *RunnerManagment) deleteRunner(id websocketID) {
	ro.rmMu.Lock()
	ro.count--
	delete(ro.runnerMap, id)
	ro.rmMu.Unlock()
}

func (ro *RunnerManagment) checkInRunner(id websocketID, arch string) {
	ro.rrMu.Lock()
	ro.runnersReadyMap[id] = arch
	ro.rrMu.Unlock()
}

// checkOutRunner returns the first websocketID of a runner which supports the asked arch
func (ro *RunnerManagment) checkOutRunner(arch string) (websocketID, bool) {
	ro.rrMu.Lock()
	defer ro.rrMu.Unlock()
	for id, sArch := range ro.runnersReadyMap {
		if sArch == arch {
			delete(ro.runnersReadyMap, id) //remove the runner so another job does not check it out
			return id, true
		}
	}
	return "", false
}

func (ro *RunnerManagment) manualDeleteRunnerReady(id websocketID) {
	ro.rrMu.Lock()
	delete(ro.runnersReadyMap, id)
	ro.rrMu.Unlock()
}
