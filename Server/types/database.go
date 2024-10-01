package types

import (
	"time"

	"github.com/google/uuid"
)

const (
	Failed     JobStatus = "failed" //received from runner - bad malware/does not run or ctx length violation
	Timeout    JobStatus = "timeout"
	LLMTimeout JobStatus = "llm_timeout"
	Running    JobStatus = "running"
	Success    JobStatus = "success"
	Pending    JobStatus = "pending"
	NoEvents   JobStatus = "no_events"

	//LLM models
	LLama3_1_8B         = "llama3.1:8b"
	LLama3_1_8B_Ctx_Len = 128000
)

type (
	JobStatus string

	//Server specific structs
	JobInfo struct {
		JobID                uuid.UUID `json:"jobID"`
		Name                 string    `json:"name"` //User modifiable defaults to uuid
		SHA256               string    `json:"sha256"`
		RunCommand           bool      `json:"run_command"`
		RunCommandArgs       []string  `json:"run_command_args"`
		FileArgs             []string  `json:"file_args"`
		Arch                 string    `json:"arch"`
		RunDuration          int       `json:"run_duration"`
		LLMResponse          []byte    `json:"llm_response"`
		SaveCMDOutput        bool      `json:"save_cmd_output"`
		Status               JobStatus `json:"job_status"`
		CreatedTime          time.Time `json:"created_time"`
		SystemPromptOverride string    `json:"system_prompt_override"`
	}

	SystemSettings struct {
		ID           uuid.UUID `json:"id"`
		Name         string    `json:"name"`
		Model        string    `json:"model"`
		TopK         float64   `json:"top_k"`
		TopP         float64   `json:"top_p"`
		Temperature  float64   `json:"temperature"`
		RepeatPen    float64   `json:"repeat_pen"`
		CtxLen       int       `json:"ctx_length"`
		SystemPrompt string    `json:"system_prompt"`
	}
)

var JobStatusMap = map[string]JobStatus{
	"failed":      Failed,
	"timeout":     Timeout,
	"llm_timeout": LLMTimeout,
	"running":     Running,
	"success":     Success,
	"pending":     Pending,
	"no_events":   NoEvents,
}

var SupportedLLMModelsMap = map[string]int{
	LLama3_1_8B: LLama3_1_8B_Ctx_Len,
}
