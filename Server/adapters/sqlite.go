package adapters

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"kairos-server/types"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

const (
	sqlitePath = "data/kairos.sqlite"
)

type (
	SQLiteAdapter struct {
		db *sql.DB
		Mu *sync.Mutex
	}

	SQL interface {
		InsertJobData(types.JobData) error
		RetrieveJobData(uuid.UUID) (*types.JobData, error)
		InsertStdoutData(types.StdoutData) error
		RetrieveStdoutData(uuid.UUID) (*types.StdoutData, error)
		InsertForkData(types.JobForkData) error
		RetrieveForkData(uuid.UUID) (*[]types.JobForkData, error)
		InsertJobMetadata(types.JobMetadata) error
		RetrieveJobMetadata(uuid.UUID) (*types.JobMetadata, error)
		InsertJobInfo(types.JobInfo) error
		RetrieveJobInfo(uuid.UUID) (*types.JobInfo, error)
		RetrieveJobInfoPromptOverride(uuid.UUID) (*string, error)
		UpdateJobInfoName(uuid.UUID, string) error
		UpdateJobStatus(uuid.UUID, types.JobStatus) error
		UpdateJobInfoLLMResponse(uuid.UUID, []byte) error
		RetrieveAllJobs() (*[]types.JobInfo, error)
		RetrieveAllWithJobStatus(types.JobStatus) (*[]types.JobInfo, error)
		DeleteJobByID(uuid.UUID) error
		StartJobStatusUpdater(context.Context, types.JobStatus)
		SaveSystemSetting(types.SystemSettings) error
		GetSystemSetting() (*types.SystemSettings, error)
		Close()
	}
)

func ConnectToSqlite() (SQL, error) {
	db, err := sql.Open("sqlite3", sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open sqlite db: %v", err)
	}

	sqla := SQLiteAdapter{
		db: db,
		Mu: &sync.Mutex{},
	}

	if err = sqla.createTables(); err != nil {
		return nil, err
	}

	if err = sqla.createSystemSettingsIfEmpty(); err != nil {
		return nil, err
	}

	return &sqla, nil
}

func (s *SQLiteAdapter) Close() {
	s.db.Close()
}

/*
Table names:

	job_data -> stores malware job result

	stdout_data -> stores stdout data

	job_fork_data -> stores all the fork information for a job

	job_metadata -> stores metadata about job

	job_info -> stores data which is shown to user
*/
func (s *SQLiteAdapter) createTables() error {
	//job data table
	query := `CREATE TABLE IF NOT EXISTS job_data (
		jobID TEXT PRIMARY KEY,
		raw_data BLOB);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create job data table: %v", err)
	}

	//stdout data table
	query = `CREATE TABLE IF NOT EXISTS stdout_data (
		jobID TEXT PRIMARY KEY,
		raw_data BLOB);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create stdout data table: %v", err)
	}

	//job fork data table
	query = `CREATE TABLE IF NOT EXISTS job_fork_data (
		forkID TEXT PRIMARY KEY,
		jobID TEXT,
		raw_data BLOB);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create job_fork_data data table: %v", err)
	}
	//job metadata table
	query = `CREATE TABLE IF NOT EXISTS job_metadata (
		jobID TEXT PRIMARY KEY,
		c2Map TEXT,
		sslMap TEXT);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create job metadata table: %v", err)
	}

	//job info table
	query = `CREATE TABLE IF NOT EXISTS job_info (
		jobID TEXT PRIMARY KEY,
		name TEXT,
		sha256 TEXT,
		run_command INTEGER,
		run_command_args TEXT,
		file_args TEXT,
		arch TEXT,
		run_duration INTEGER,
		llm_response BLOB,
		save_cmd_output INTEGER,
		job_status TEXT,
		created_time TEXT,
		system_prompt_override TEXT);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create job info table: %v", err)
	}

	//settings table
	query = `CREATE TABLE IF NOT EXISTS settings (
		id TEXT PRIMARY KEY,
		name TEXT,
		model TEXT,
		top_k REAL,
		top_p REAL,
		temperature REAL,
		repeat_penalty REAL,
		ctx_length INTEGER,
		system_prompt TEXT);`
	if _, err := s.db.Exec(query); err != nil {
		return fmt.Errorf("unable to create settings table: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) createSystemSettingsIfEmpty() error {
	_, err := s.GetSystemSetting()
	if err != nil {
		if err.Error() == "no rows found" {
			log.Info("Setting Default System Settings")
			defaultSettings := types.SystemSettings{
				ID:           uuid.New(),
				Name:         "default settings",
				Model:        "llama3.1:8b",
				TopK:         40,
				TopP:         0.1,
				Temperature:  0.2,
				RepeatPen:    1.1,
				CtxLen:       20000,
				SystemPrompt: BaseSystemPrompt,
			}
			updateErr := s.SaveSystemSetting(defaultSettings)
			if updateErr != nil {
				return fmt.Errorf("unable to set default system settings: %v", updateErr)
			}
		} else {
			return fmt.Errorf("unable to retrieve default system settings: %v", err)
		}
	}
	return nil
}

func (s *SQLiteAdapter) InsertJobData(jobData types.JobData) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("INSERT INTO job_data(jobID, raw_data) VALUES(?,?)")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()

	rawData, err := json.Marshal(jobData.RawData)
	if err != nil {
		return fmt.Errorf("unable to marshal raw job data: %v", err)
	}

	_, err = stmt.Exec(jobData.JobID.String(), rawData)
	if err != nil {
		return fmt.Errorf("uanble to insert runner data: %v", err)
	}
	return nil
}

func (s *SQLiteAdapter) RetrieveJobData(jobID uuid.UUID) (*types.JobData, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	var rawData []byte

	query := "SELECT raw_data FROM job_data WHERE jobID = ?"
	err := s.db.QueryRow(query, jobID.String()).Scan(&rawData)
	if err != nil {
		return nil, fmt.Errorf("unable to get job data: %v", err)
	}

	var jobData types.JobData
	jobData.JobID = jobID

	err = json.Unmarshal(rawData, &jobData.RawData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal job data: %v", err)
	}
	return &jobData, nil
}

func (s *SQLiteAdapter) InsertStdoutData(stdoutData types.StdoutData) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("INSERT INTO stdout_data(jobID, raw_data) VALUES(?,?)")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()
	rawData, err := json.Marshal(stdoutData.RawData)
	if err != nil {
		return fmt.Errorf("unable to marshal stdout job data: %v", err)
	}
	_, err = stmt.Exec(stdoutData.JobID.String(), rawData)
	if err != nil {
		return fmt.Errorf("unable to insert stdout data: %v", err)
	}
	return nil
}

func (s *SQLiteAdapter) RetrieveStdoutData(jobID uuid.UUID) (*types.StdoutData, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	var rawData []byte

	query := "SELECT raw_data FROM stdout_data WHERE jobID = ?"
	err := s.db.QueryRow(query, jobID.String()).Scan(&rawData)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to get stdout data: %v", err)
	}

	var stdoutData types.StdoutData
	stdoutData.JobID = jobID
	err = json.Unmarshal(rawData, &stdoutData.RawData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal stdout data: %v", err)
	}

	return &stdoutData, nil
}

func (s *SQLiteAdapter) InsertForkData(fork types.JobForkData) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("INSERT INTO job_fork_data(forkID, jobID, raw_data) VALUES(?,?,?)")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()
	rawData, err := json.Marshal(fork.RawData)
	if err != nil {
		return fmt.Errorf("unable to marshal fork data: %v", err)
	}
	_, err = stmt.Exec(fork.ForkID.String(), fork.JobID.String(), rawData)
	if err != nil {
		return fmt.Errorf("unable to insert fork data: %v", err)
	}
	return nil
}

func (s *SQLiteAdapter) RetrieveForkData(jobID uuid.UUID) (*[]types.JobForkData, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	query := "SELECT forkID, raw_data FROM job_fork_data WHERE jobID = ?"
	rows, err := s.db.Query(query, jobID.String())
	if err != nil {
		return nil, fmt.Errorf("unable to get fork data: %v", err)
	}
	var forks []types.JobForkData
	for rows.Next() {
		var rawForkID string
		var rawData []byte

		err := rows.Scan(&rawForkID, &rawData)
		if err != nil {
			return nil, fmt.Errorf("unable to scan fork data: %v", err)
		}

		forkID, err := uuid.Parse(rawForkID)
		if err != nil {
			return nil, fmt.Errorf("unable to convert forkID to uuid: %v", err)
		}

		tempFork := types.JobForkData{
			JobID:  jobID,
			ForkID: forkID,
		}

		err = json.Unmarshal(rawData, &tempFork.RawData)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal fork raw data: %v", err)
		}

		forks = append(forks, tempFork)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("encountered errors while retreiving fork data: %v", err)
	}

	return &forks, nil
}

func (s *SQLiteAdapter) InsertJobMetadata(metadata types.JobMetadata) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	c2MapJson, err := json.Marshal(metadata.C2IPPMap)
	if err != nil {
		return fmt.Errorf("unable to marshal c2 map: %v", err)
	}

	sslMapJson, err := json.Marshal(metadata.SSLMap)
	if err != nil {
		return fmt.Errorf("unable to marshal ssl map: %v", err)
	}
	_, err = s.db.Exec("INSERT INTO job_metadata (jobID, c2Map, sslMap) VALUES (?,?,?)", metadata.JobID, c2MapJson, sslMapJson)
	if err != nil {
		return fmt.Errorf("unable to insert job metadata: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) RetrieveJobMetadata(jobID uuid.UUID) (*types.JobMetadata, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	var metadata types.JobMetadata
	var c2MapJSON, sslMapJson string

	query := "SELECT c2Map, sslMap FROM job_metadata WHERE jobID = ?"
	row := s.db.QueryRow(query, jobID.String())
	err := row.Scan(&c2MapJSON, &sslMapJson)
	if err != nil {
		return nil, fmt.Errorf("unable to scan job metadata: %v", err)
	}

	metadata.JobID = jobID

	if err := json.Unmarshal([]byte(c2MapJSON), &metadata.C2IPPMap); err != nil {
		return nil, fmt.Errorf("unable to unmarshal c2 data: %v", err)
	}

	if err := json.Unmarshal([]byte(sslMapJson), &metadata.SSLMap); err != nil {
		return nil, fmt.Errorf("unable to unmarshal ssl data: %v", err)
	}

	return &metadata, nil
}

func (s *SQLiteAdapter) InsertJobInfo(job types.JobInfo) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	stmt, err := s.db.Prepare("INSERT INTO job_info(jobID, name, sha256, run_command, run_command_args, file_args, arch, run_duration, llm_response, save_cmd_output, job_status, created_time, system_prompt_override) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()
	//llm response will be empty on initial insert

	runCommandInt := 0
	if job.RunCommand {
		runCommandInt = 1
	}

	saveCMDOutputInt := 0
	if job.SaveCMDOutput {
		saveCMDOutputInt = 1
	}

	fileArgsJson, err := json.Marshal(job.FileArgs)
	if err != nil {
		return fmt.Errorf("unable to marshal file args: %v", err)
	}

	commandArgsJson, err := json.Marshal(job.RunCommandArgs)
	if err != nil {
		return fmt.Errorf("unable to marshal command args: %v", err)
	}

	_, err = stmt.Exec(job.JobID.String(), job.Name, job.SHA256, runCommandInt, commandArgsJson, fileArgsJson, job.Arch, job.RunDuration, "", saveCMDOutputInt, string(job.Status), job.CreatedTime.Format("2006-01-02 15:04:05"), job.SystemPromptOverride)
	if err != nil {
		return fmt.Errorf("unable to insert job info: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) RetrieveJobInfo(jobID uuid.UUID) (*types.JobInfo, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var jobInfo types.JobInfo
	var rawLLMResponse []byte
	var tempID string
	var rawRunCommand = 0
	var rawSaveCMDOutput = 0
	var rawCommandArgsJson, rawFileArgsJson, rawStatus, rawCreatedTime string

	query := "SELECT jobID, name, sha256, run_command, run_command_args, file_args, arch, run_duration, llm_response, save_cmd_output, job_status, created_time, system_prompt_override FROM job_info WHERE jobID = ?"
	err := s.db.QueryRow(query, jobID.String()).Scan(&tempID, &jobInfo.Name, &jobInfo.SHA256, &rawRunCommand, &rawCommandArgsJson, &rawFileArgsJson, &jobInfo.Arch, &jobInfo.RunDuration, &rawLLMResponse, &rawSaveCMDOutput, &rawStatus, &rawCreatedTime, &jobInfo.SystemPromptOverride)
	if err != nil {
		return nil, fmt.Errorf("unable to get job info: %v", err)
	}

	jobInfo.JobID = jobID
	if rawRunCommand != 0 {
		jobInfo.RunCommand = true
	}

	if rawSaveCMDOutput != 0 {
		jobInfo.SaveCMDOutput = true
	}

	if err := json.Unmarshal([]byte(rawCommandArgsJson), &jobInfo.RunCommandArgs); err != nil {
		return nil, fmt.Errorf("unmarshal run command args: %v", err)
	}

	if err := json.Unmarshal([]byte(rawFileArgsJson), &jobInfo.FileArgs); err != nil {
		return nil, fmt.Errorf("unmarshal file args: %v", err)
	}

	if len(rawLLMResponse) > 0 {
		err = json.Unmarshal(rawLLMResponse, &jobInfo.LLMResponse)
		if err != nil {
			return nil, fmt.Errorf("unmarshal job info: %v", err)
		}
	}

	parsedTime, err := time.Parse("2006-01-02 15:04:05", rawCreatedTime)
	if err != nil {
		return nil, fmt.Errorf("unable to parse created time: %v", err)
	}
	jobInfo.CreatedTime = parsedTime

	status, err := stringToStatus(rawStatus)
	if err != nil {
		return nil, fmt.Errorf("unable to parse job status: %v", err)
	}
	jobInfo.Status = *status

	return &jobInfo, nil
}

func (s *SQLiteAdapter) RetrieveJobInfoPromptOverride(jobID uuid.UUID) (*string, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var rawPromptOverride string

	query := "SELECT system_prompt_override from job_info WHERE jobID = ?"
	err := s.db.QueryRow(query, jobID.String()).Scan(&rawPromptOverride)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve system prompt override for job: %v err: %v", jobID, err)
	}

	return &rawPromptOverride, nil
}

func (s *SQLiteAdapter) UpdateJobInfoName(jobID uuid.UUID, newName string) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("UPDATE job_info SET name = ? WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(newName, jobID.String())
	if err != nil {
		return fmt.Errorf("unable to update job info name: %v", err)
	}
	return nil
}

func (s *SQLiteAdapter) UpdateJobInfoLLMResponse(jobID uuid.UUID, llmResponse []byte) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("UPDATE job_info SET llm_response = ? WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statment: %v", err)
	}
	defer stmt.Close()

	rawLLMResponse, err := json.Marshal(llmResponse)
	if err != nil {
		return fmt.Errorf("unable to marshal llm info: %v", err)
	}
	_, err = stmt.Exec(rawLLMResponse, jobID.String())
	if err != nil {
		return fmt.Errorf("unable to update job info llm response: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) UpdateJobStatus(jobID uuid.UUID, status types.JobStatus) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("UPDATE job_info SET job_status = ? WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement: %v", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(string(status), jobID.String())
	if err != nil {
		return fmt.Errorf("unable to update job_status: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) RetrieveAllJobs() (*[]types.JobInfo, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	query := "SELECT jobID, name, sha256, run_command, run_command_args, file_args, arch, run_duration, llm_response, save_cmd_output, job_status, created_time FROM job_info ORDER BY created_time DESC"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve job infos: %v", err)
	}
	var jobs []types.JobInfo
	for rows.Next() {
		var tempID string
		var tempRunCommand = 0
		var tempSaveCMDOutput = 0
		var rawLLMResponse []byte
		var rawCommandArgsJson, rawFileArgsJson, rawStatus, rawCreatedTime string
		var job types.JobInfo

		err := rows.Scan(&tempID, &job.Name, &job.SHA256, &tempRunCommand, &rawCommandArgsJson, &rawFileArgsJson, &job.Arch, &job.RunDuration, &rawLLMResponse, &tempSaveCMDOutput, &rawStatus, &rawCreatedTime)
		if err != nil {
			return nil, fmt.Errorf("uanble to scan job info: %v", err)
		}

		jobID, err := uuid.Parse(tempID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse jobID: %v", err)
		}
		job.JobID = jobID

		if tempRunCommand != 0 {
			job.RunCommand = true
		}

		if tempSaveCMDOutput != 0 {
			job.SaveCMDOutput = true
		}

		if err := json.Unmarshal([]byte(rawCommandArgsJson), &job.RunCommandArgs); err != nil {
			return nil, fmt.Errorf("unmarshal run command args: %v", err)
		}

		if err := json.Unmarshal([]byte(rawFileArgsJson), &job.FileArgs); err != nil {
			return nil, fmt.Errorf("unmarshal file args: %v", err)
		}

		if len(rawLLMResponse) > 0 {
			err = json.Unmarshal(rawLLMResponse, &job.LLMResponse)
			if err != nil {
				return nil, fmt.Errorf("unable to unmarshal llm response: %v", err)
			}
		}

		parsedTime, err := time.Parse("2006-01-02 15:04:05", rawCreatedTime)
		if err != nil {
			return nil, fmt.Errorf("unable to parse created time: %v", err)
		}
		job.CreatedTime = parsedTime

		status, err := stringToStatus(rawStatus)
		if err != nil {
			return nil, fmt.Errorf("unable to parse status: %v", err)
		}
		job.Status = *status

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("encountered errors while retreiving all job data: %v", err)
	}

	return &jobs, nil
}

func (s *SQLiteAdapter) RetrieveAllWithJobStatus(status types.JobStatus) (*[]types.JobInfo, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	query := "SELECT jobID, run_duration, created_time FROM job_info WHERE job_status = ?"
	rows, err := s.db.Query(query, string(status))
	if err != nil {
		return nil, fmt.Errorf("unable to get all jobs with status: %v err: %v", status, err)
	}
	var jobIDs []types.JobInfo
	for rows.Next() {
		var rawJobID, rawCreatedTime string
		var runDuration int

		err := rows.Scan(&rawJobID, &runDuration, &rawCreatedTime)
		if err != nil {
			return nil, fmt.Errorf("unable to scan job status: %v", err)
		}

		jobID, err := uuid.Parse(rawJobID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse job status id: %v", err)
		}

		parsedTime, err := time.Parse("2006-01-02 15:04:05", rawCreatedTime)
		if err != nil {
			return nil, fmt.Errorf("unable to parse created time: %v", err)
		}

		jobIDs = append(jobIDs, types.JobInfo{
			JobID:       jobID,
			RunDuration: runDuration,
			CreatedTime: parsedTime,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("encountered errors while retreiving jobs with status data: %v", err)
	}

	return &jobIDs, nil
}

func (s *SQLiteAdapter) DeleteJobByID(id uuid.UUID) error {
	// job_data
	jobDataStmt, err := s.db.Prepare("DELETE FROM job_data WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement to delete from job_data: %v", err)
	}
	defer jobDataStmt.Close()

	_, err = jobDataStmt.Exec(id.String())
	if err != nil {
		return fmt.Errorf("unable to delete job_data rows: %v", err)
	}

	//stdout_data
	stdoutDataStmt, err := s.db.Prepare("DELETE FROM stdout_data WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement to delete from stdout_data: %v", err)
	}
	defer stdoutDataStmt.Close()

	_, err = stdoutDataStmt.Exec(id.String())
	if err != nil {
		return fmt.Errorf("unable to delete stdout_data rows: %v", err)
	}

	//job_fork_data
	jobForkDataStmt, err := s.db.Prepare("DELETE FROM job_fork_data WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement to delete from job_fork_data: %v", err)
	}
	defer jobForkDataStmt.Close()

	_, err = jobForkDataStmt.Exec(id.String())
	if err != nil {
		return fmt.Errorf("unable to delete job_fork_data rows: %v", err)
	}

	//job_metadata
	jobMetaStmt, err := s.db.Prepare("DELETE FROM job_metadata WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement to delete from job_metadata: %v", err)
	}
	defer jobMetaStmt.Close()

	_, err = jobMetaStmt.Exec(id.String())
	if err != nil {
		return fmt.Errorf("unable to delete job_metadata rows: %v", err)
	}

	//job_info
	jobInfoStmt, err := s.db.Prepare("DELETE FROM job_info WHERE jobID = ?")
	if err != nil {
		return fmt.Errorf("unable to create statement to delete from job_info: %v", err)
	}
	defer jobInfoStmt.Close()

	_, err = jobInfoStmt.Exec(id.String())
	if err != nil {
		return fmt.Errorf("unable to delete job_info rows: %v", err)
	}

	return nil
}

func (s *SQLiteAdapter) StartJobStatusUpdater(ctx context.Context, statusToUpdate types.JobStatus) {
	updateTicker := time.NewTicker(60 * time.Second)
	defer updateTicker.Stop()

cleaner:
	for {
		select {
		case <-updateTicker.C:
			jobs, err := s.RetrieveAllWithJobStatus(statusToUpdate)
			if err != nil {
				log.Errorf("job status updater unable to retrieve jobs: %v", err)
				break cleaner
			}

			timeNow := time.Now().UTC()
			for _, job := range *jobs {
				if timeNow.After(job.CreatedTime.Add(time.Duration(job.RunDuration) + (5 * time.Minute))) {
					err := s.UpdateJobStatus(job.JobID, types.Timeout)
					if err != nil {
						log.Errorf("job status updater unable to update job: %v", err)
					}
				}
			}

		case <-ctx.Done():
			break cleaner
		}
	}
}

func stringToStatus(s string) (*types.JobStatus, error) {
	if status, ok := types.JobStatusMap[s]; ok {
		return &status, nil
	}
	return nil, fmt.Errorf("unable to find color")
}

func (s *SQLiteAdapter) SaveSystemSetting(setting types.SystemSettings) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	stmt, err := s.db.Prepare("INSERT INTO settings (id, name, model, top_k, top_p, temperature, repeat_penalty, ctx_length, system_prompt) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET name = excluded.name, model = excluded.model, top_k = excluded.top_k, top_p = excluded.top_p, temperature = excluded.temperature, repeat_penalty = excluded.repeat_penalty, ctx_length = excluded.ctx_length, system_prompt = excluded.system_prompt")
	if err != nil {
		return fmt.Errorf("unable to create statementL: %v", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(setting.ID.String(), setting.Name, setting.Model, setting.TopK, setting.TopP, setting.Temperature, setting.RepeatPen, setting.CtxLen, setting.SystemPrompt)
	if err != nil {
		return fmt.Errorf("unable to insert system setting: %v", err)
	}
	return nil
}

func (s *SQLiteAdapter) GetSystemSetting() (*types.SystemSettings, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	row := s.db.QueryRow("SELECT id, name, model, top_k, top_p, temperature, repeat_penalty, ctx_length, system_prompt FROM settings")

	var rawID string
	var rs types.SystemSettings
	err := row.Scan(&rawID, &rs.Name, &rs.Model, &rs.TopK, &rs.TopP, &rs.Temperature, &rs.RepeatPen, &rs.CtxLen, &rs.SystemPrompt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no rows found")
		}
		return nil, fmt.Errorf("unable to retrieve system settings: %v", err)
	}

	id, err := uuid.Parse(rawID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse setting id: %v", err)
	}
	rs.ID = id

	return &rs, nil
}
