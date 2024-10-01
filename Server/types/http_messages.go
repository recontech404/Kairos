package types

import (
	"time"

	"github.com/google/uuid"
)

type (
	DashboardResponse struct {
		RunnersOnlineCnt int `json:"runners_online_cnt"`
	}

	RunnersResponse struct {
		RunnersOnlineInfo []RunnerData `json:"runners_online_info"`
	}

	JobResponse struct {
		JobID                uuid.UUID `json:"jobID"`
		Name                 string    `json:"name"` //User modifiable defaults to uuid
		SHA256               string    `json:"sha256"`
		RunCommand           bool      `json:"run_command"`
		RunCommandArgs       []string  `json:"run_command_args"`
		FileArgs             []string  `json:"file_args"`
		Arch                 string    `json:"arch"`
		RunDuration          int       `json:"run_duration"`
		LLMResponse          string    `json:"llm_response"`
		SaveCMDOutput        bool      `json:"save_cmd_output"`
		Status               JobStatus `json:"job_status"`
		CreatedTime          time.Time `json:"created_time"`
		SystemPromptOverride string    `json:"system_prompt_override"`
	}

	UIAddJob struct {
		KeepAlive            bool   `json:"keep_alive"`
		RunDuration          int    `json:"run_duration"`
		RunCommand           bool   `json:"run_command"` //run command instead of file for fileless exploits
		RunCommandArgs       string `json:"run_command_args"`
		MalwareFile          string `json:"malware_file"`
		FileArgs             string `json:"file_args"`
		Name                 string `json:"name"`
		Arch                 string `json:"arch"`
		SaveCMDOutput        bool   `json:"save_cmd_output"`
		BinExclusions        string `json:"bin_exclusions"`
		SystemPromptOverride string `json:"system_prompt_override"`
	}

	UIRequestWithUUID struct {
		JobID string `json:"jobID"`
	}

	UICMDDataResponse struct {
		JobID   uuid.UUID `json:"jobID"`
		CMDData string    `json:"cmd_data"`
	}
)
