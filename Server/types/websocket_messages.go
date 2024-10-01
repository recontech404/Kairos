package types

import (
	"encoding/json"

	"github.com/google/uuid"
)

type (
	//Shared structs between runner and server
	MalwareJob struct {
		JobID          uuid.UUID `json:"jobID"`
		KeepAlive      bool      `json:"keep_alive"`
		RunDuration    int       `json:"run_duration"`
		RunCommand     bool      `json:"run_command"` //run command instead of file for fileless exploits
		RunCommandArgs []string  `json:"run_command_args"`
		MalwareFile    []byte    `json:"malware_file"`
		FileArgs       []string  `json:"file_args"`
		SaveCMDOutput  bool      `json:"save_cmd_output"`
		RunCommandEL   []string  `json:"run_command_exclusion_list"`
	}

	RunnerData struct {
		SystemID    string `json:"systemID"`
		Hostname    string `json:"hostname"`
		Arch        string `json:"arch"`
		EBPFSupport bool   `json:"ebpf_support"`
		RunnerIP    string `json:"runner_ip"` //populated by server to support multiple nics
	}

	JobData struct {
		JobID   uuid.UUID `json:"jobID"`
		RawData []byte    `json:"raw_data"`
	}

	StdoutData struct {
		JobID   uuid.UUID `json:"jobID"`
		RawData []byte    `json:"raw_data"`
	}

	JobForkData struct {
		ForkID  uuid.UUID `json:"forkID"`
		JobID   uuid.UUID `json:"jobID"`
		RawData []byte    `json:"raw_data"`
	}

	JobMetadata struct {
		JobID    uuid.UUID      `json:"jobID"`
		C2IPPMap map[string]int `json:"c2_ipp_map"`
		SSLMap   map[int]string `json:"ssl_map"`
	}

	RunnerJIDM struct {
		JobID uuid.UUID `json:"jobID"`
	}

	WSData struct {
		Type WSDataType      `json:"type"`
		Data json.RawMessage `json:"data"`
	}

	WSDataType string
)

const (
	MalwareJobMsg        WSDataType = "malware_job"
	MalwareRunFailure    WSDataType = "malware_run_failure"
	RunnerInfoMsg        WSDataType = "runner_info_msg"
	JobDataMsg           WSDataType = "job_data_msg"
	StdoutDataMsg        WSDataType = "stdout_data_msg"
	JobForkDataMsg       WSDataType = "job_fork_data_msg"
	JobMetadataMsg       WSDataType = "job_metadata_msg"
	RunnerDoneSendingMsg WSDataType = "runner_done_sending_msg"
)
