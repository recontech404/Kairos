package adapters

import (
	"context"
	"encoding/json"
	"kairos-server/types"
	"time"

	log "github.com/sirupsen/logrus"
)

func (w *MultiWSHandler) listenToRunnerMessages(ctx context.Context, id websocketID, runnerIP string) {
listen:
	for {
		select {
		case <-ctx.Done():
			break listen
		default:
			rawMsg, err := w.readMessage(id)
			if err != nil {
				log.Errorf("unable to read message from websocket from runner IP: %s - err: %v", runnerIP, err)
				w.Disconnect(id)
				break listen
			}
			if rawMsg != nil {
				var data types.WSData
				err = json.Unmarshal(rawMsg, &data)
				if err != nil {
					log.Errorf("unable to unmarshal message from runner: %v", err)
					continue
				}
				switch data.Type {
				case types.RunnerInfoMsg:
					log.Info("Received runner info msg")
					go w.processRunnerInfoMsg(id, data.Data, runnerIP)
				case types.JobDataMsg:
					log.Info("Received job data msg")
					go w.processJobDataMsg(data.Data)
				case types.StdoutDataMsg:
					log.Info("Received stdout data msg")
					go w.processStdoutDataMsg(data.Data)
				case types.JobForkDataMsg:
					log.Info("Received job fork data msg")
					go w.processJobForkDataMsg(data.Data)
				case types.JobMetadataMsg:
					log.Info("Received job metadata msg")
					go w.processJobMetadataMsg(data.Data)
				case types.RunnerDoneSendingMsg:
					log.Info("Received runner done sending msg")
					go w.requestLLMAnalysis(data.Data)
				case types.MalwareRunFailure:
					log.Info("Received runner malware run fail msg")
					go w.processMalwareRunFailure(data.Data)
				default:
					log.Errorf("Received unknown msg type: %v", data.Type)
				}
			} else {
				break listen //websocket closed normally
			}
		}
	}
}

func (w *MultiWSHandler) processRunnerInfoMsg(id websocketID, rawData []byte, runnerIP string) {
	var runner types.RunnerData
	if err := json.Unmarshal(rawData, &runner); err != nil {
		log.Errorf("unable to unmarshal runner info msg: %v", err)
		return
	}
	runner.RunnerIP = runnerIP
	runner.SystemID = string(id)
	w.rm.addRunner(id, runner)
	if runner.EBPFSupport {
		w.rm.checkInRunner(id, runner.Arch) //check-in runner to accept incoming jobs
	}
}

func (w *MultiWSHandler) processJobDataMsg(rawData []byte) {
	var msg types.JobData
	err := json.Unmarshal(rawData, &msg)
	if err != nil {
		log.Errorf("unable to unmarshal job data msg: %v", err)
		return
	}
	if err = w.sql.InsertJobData(msg); err != nil {
		log.Errorf("unable to insert job data to db: %v", err)
		return
	}
}

func (w *MultiWSHandler) processStdoutDataMsg(rawData []byte) {
	var msg types.StdoutData
	err := json.Unmarshal(rawData, &msg)
	if err != nil {
		log.Errorf("unable to unmarshal job data msg: %v", err)
		return
	}
	if err = w.sql.InsertStdoutData(msg); err != nil {
		log.Errorf("unable to insert job data to db: %v", err)
		return
	}
}

func (w *MultiWSHandler) processJobForkDataMsg(rawData []byte) {
	var msg types.JobForkData
	err := json.Unmarshal(rawData, &msg)
	if err != nil {
		log.Errorf("unable to unmarshal job data msg: %v", err)
		return
	}
	if err = w.sql.InsertForkData(msg); err != nil {
		log.Errorf("unable to insert job data to db: %v", err)
		return
	}
}

func (w *MultiWSHandler) processJobMetadataMsg(rawData []byte) {
	var msg types.JobMetadata
	err := json.Unmarshal(rawData, &msg)
	if err != nil {
		log.Errorf("unable to unmarshal job data msg: %v", err)
		return
	}
	if err = w.sql.InsertJobMetadata(msg); err != nil {
		log.Errorf("unable to insert job data to db: %v", err)
		return
	}
}

func (w *MultiWSHandler) requestLLMAnalysis(rawData []byte) {
	var msg types.RunnerJIDM
	if err := json.Unmarshal(rawData, &msg); err != nil {
		log.Errorf("unable to unmarshal runner done sending msg: %v", err)
		return
	}

	time.Sleep(2 * time.Second) //TODO remove sleep

	mainJobData, err := w.sql.RetrieveJobData(msg.JobID)
	if err != nil {
		log.Errorf("unable to retrieve job data for llm jobID: %s : %v", msg.JobID, err)
		return
	}

	if len(mainJobData.RawData) <= 0 {
		log.Warn("Skipping LLM analysis as no eBPF tracepoint events")
		w.sql.UpdateJobStatus(msg.JobID, types.NoEvents)
		return
	}

	sysSettings, err := w.sql.GetSystemSetting()
	if err != nil {
		log.Errorf("unable to retrieve system settings for llm: %v", err)
		return
	}

	//TODO retrieve fork
	numTokens := len(w.llm.Tke.Encode(string(mainJobData.RawData), nil, nil))
	if numTokens > 10000 {
		log.Warnf("Warning ---> %d tokens received, LLM may lose context", numTokens)
	}

	if numTokens >= (sysSettings.CtxLen - 100) {
		log.Warnf("WARNING ---> %d tokens is not allowed - over context length", numTokens)
		w.sql.UpdateJobStatus(msg.JobID, types.Failed)
		return
	}

	systemPromptOverride, err := w.sql.RetrieveJobInfoPromptOverride(msg.JobID)
	if err != nil {
		log.Errorf("unable to retrieve system prompt override check: %v", err)
		return
	}

	log.Infof("Requesting LLM Analysis for job: %s.......... Tokens: %d\n", msg.JobID, numTokens)
	llmResponse, err := SendLLMRequest(*w.llm.Client, sysSettings.Model, mainJobData.RawData, sysSettings.TopK, sysSettings.TopP, sysSettings.Temperature, sysSettings.RepeatPen, sysSettings.CtxLen, *systemPromptOverride)
	if err != nil {
		w.sql.UpdateJobStatus(msg.JobID, types.LLMTimeout)
		log.Errorf("LLM response err: %v", err)
		return
	}

	if err = w.sql.UpdateJobInfoLLMResponse(msg.JobID, llmResponse); err != nil {
		log.Errorf("unable to update llm response: %v", err)
		return
	}

	if err = w.sql.UpdateJobStatus(msg.JobID, types.Success); err != nil {
		log.Errorf("unable ot update job status: %v", err)
		return
	}

	log.Infof("Received LLM Analysis for job: %s", msg.JobID)
}

func (w *MultiWSHandler) processMalwareRunFailure(rawData []byte) {
	var msg types.RunnerJIDM
	if err := json.Unmarshal(rawData, &msg); err != nil {
		log.Errorf("unable to unmarshal runner malware run fail msg: %v", err)
		return
	}

	if err := w.sql.UpdateJobStatus(msg.JobID, types.Failed); err != nil {
		log.Errorf("unable to update job status: %v", err)
		return
	}
}
