package extractors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"kairos-runner/adapters"
	"kairos-runner/types"
	"os/exec"
	"time"

	memexec "github.com/amenzhinsky/go-memexec"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func StartJobListener(ctx context.Context, wsh *adapters.WSHandler, jobDone chan struct{}, shutdown chan<- struct{}, shutdownNoTerm chan<- struct{}) {
listen:
	for {
		select {
		case <-ctx.Done():
			break listen
		default:
			msg, err := wsh.ReadMessage()
			if err != nil {
				log.Warnf("lost connection - retrying")
				err = wsh.Connect(ctx)
				if err != nil {
					log.Fatalf("unable to re-connect websocket: %v", err)
				}
				continue
			}
			if msg != nil {
				var wsData types.WSData
				err = json.Unmarshal(msg, &wsData)
				if err != nil {
					log.Fatalf("unable to unmarshal raw job: %v", err)
				}
				switch wsData.Type {
				case types.MalwareJobMsg:
					if !runningJob() {
						setRunningJobTrue()
						go processMalwareMsg(ctx, wsData.Data, wsh, jobDone, shutdown, shutdownNoTerm)
					} else {
						log.Warn("Got another message to start job while one is currently running")
					}

				default:
					log.Warnf("received unknown ws type: %v\n", wsData.Type)
				}
			} else {
				break listen //websocket must be closed
			}
		}
	}
}

func processMalwareMsg(ctx context.Context, data json.RawMessage, wsh *adapters.WSHandler, jobDone chan struct{}, shutdown chan<- struct{}, shutdownNoTerm chan<- struct{}) {
	var job types.MalwareJob
	err := json.Unmarshal(data, &job)
	if err != nil {
		log.Fatalf("unable to unmarshal job: %v", err)
	}

	setGlobalJobID(job.JobID)

	err = runMalwareJob(ctx, job, wsh)
	if err == fmt.Errorf("ctx cancel") {
		return
	} else if err != nil {
		log.Fatalf("unable to start job: %v", err)
	}

	for i := 0; i < getJobDoneListenerCount(); i++ {
		jobDone <- struct{}{}
	}

	if job.KeepAlive {
		shutdownNoTerm <- struct{}{}
	} else {
		shutdown <- struct{}{}
	}
}

func runMalwareJob(ctx context.Context, job types.MalwareJob, wsh *adapters.WSHandler) error {
	ticker := time.NewTicker(time.Duration(job.RunDuration) * time.Second)
	defer ticker.Stop()
	malCtx, malCancel := context.WithCancel(context.Background())
	var cmdStdout bytes.Buffer

	if !job.RunCommand {
		log.Printf("Starting Malware Job With Args -> %s", job.FileArgs)
		exe, err := memexec.New(job.MalwareFile)
		if err != nil {
			return fmt.Errorf("unable to memexec: %v", err)
		}
		cmd := exe.CommandContext(malCtx, job.FileArgs...)
		cmd.Stdout = &cmdStdout
		err = cmd.Start()
		if err != nil {
			sendErr := sendMalwareFailedToRunMsg(ctx, job.JobID, wsh)
			if err != nil {
				log.Warnf("%v", sendErr)
			}
			return fmt.Errorf("unable to start malware file: %v", err)
		}
		addPidToFilter(uint32(cmd.Process.Pid))
		for {
			select {
			case <-ticker.C:
				log.Info("Terminating Malware As Run Duration Reached")
				malCancel()
				if job.SaveCMDOutput {
					sendCMDOutputData(ctx, job.JobID, &cmdStdout, wsh)
				}
				return nil
			case <-ctx.Done():
				log.Warn("Context Termination Received While Running Malware")
				malCancel()
				return fmt.Errorf("ctx cancel")
			}
		}
	} else {
		if len(job.RunCommandArgs) < 1 {
			return fmt.Errorf("no run command args supplied")
		}

		setRunCommandSyscallELTrue() //to not capture read events

		if len(job.RunCommandEL) > 0 {
			setGlobalBinExclusions(job.RunCommandEL)
			log.Infof("Adding Bin Exclusions: %v", job.RunCommandEL)
		}
		log.Printf("Starting Malware Job With Args -> %v", job.RunCommandArgs)
		var args []string
		bin := job.RunCommandArgs[0]

		if len(job.RunCommandArgs) > 1 {
			args = job.RunCommandArgs[1:]
		}
		cmd := exec.CommandContext(malCtx, bin, args...)
		cmd.Stdout = &cmdStdout
		err := cmd.Start()
		if err != nil {
			sendErr := sendMalwareFailedToRunMsg(ctx, job.JobID, wsh)
			if err != nil {
				log.Warnf("%v", sendErr)
			}
			return fmt.Errorf("unable to start malware cmd: %v", err)
		}
		addBenignPid((uint32(cmd.Process.Pid)))
		for {
			select {
			case <-ticker.C:
				log.Info("Terminating Malware As Run Duration Reached")
				if cmd.Process != nil {
					malCancel()
				}

				if job.SaveCMDOutput {
					sendCMDOutputData(ctx, job.JobID, &cmdStdout, wsh)
				}
				return nil
			case <-ctx.Done():
				log.Warn("Context Termination Received While Running Malware")
				if cmd.Process != nil {
					malCancel()
				}
				return fmt.Errorf("ctx cancel")
			}
		}
	}
}

func sendCMDOutputData(ctx context.Context, id uuid.UUID, data *bytes.Buffer, wsh *adapters.WSHandler) {
	var rawCMDData = types.StdoutData{
		JobID:   id,
		RawData: data.Bytes(),
	}
	rawCMDDataMsg, err := adapters.WSMarshalObject(rawCMDData, types.StdoutDataMsg)
	if err != nil {
		log.Errorf("uanble to marshal cmd stdout data: %v", err)
		return
	}

	if err = wsh.SendMessage(ctx, rawCMDDataMsg); err != nil {
		log.Errorf("unable to send cmd stdout data: %v", err)
	}
}

func sendMalwareFailedToRunMsg(ctx context.Context, id uuid.UUID, wsh *adapters.WSHandler) error {
	var rawFailData = types.RunnerJIDM{
		JobID: id,
	}
	rawFailMsg, err := adapters.WSMarshalObject(rawFailData, types.MalwareRunFailure)
	if err != nil {
		return fmt.Errorf("unable to marshal malware failure msg: %v", err)
	}

	if err := wsh.SendMessage(ctx, rawFailMsg); err != nil {
		return fmt.Errorf("unable to send malware failure msg: %v", err)
	}
	return nil
}
