package adapters

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"kairos-server/types"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

var addShell = []string{"/bin/sh", "-c"}

const (
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

type (
	Server struct {
		HTTP      *http.Server
		WSHandler MultiWSHandler
	}

	ServerCfg struct {
		Address string
		Port    int
	}
)

func SetupHTTPServer(cfg ServerCfg, wsHandler MultiWSHandler) *Server {
	handler := gin.Default()

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Errorf("webserver listen serve err: %v", err)
		}
	}()

	server := &Server{
		HTTP:      srv,
		WSHandler: wsHandler,
	}

	handler.Use(CORSMiddleware())
	server.addRootHandles(handler)
	server.addUIHandles(handler)

	return server
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.HTTP.Shutdown(ctx)
}

func (s *Server) addRootHandles(handler *gin.Engine) {
	handler.GET("/health", s.Health) //for k8s health check
	handler.GET("/ws", s.RunnerConnect)
}

func (s *Server) addUIHandles(handler *gin.Engine) {
	dashboard := handler.Group("/ui")
	{
		dashboard.GET("/dashboard", s.UIDashboard)
		dashboard.GET("/runners", s.UIRunners)
		dashboard.GET("/jobs", s.GetJobs)
		dashboard.POST("/cmddata", s.GetCMDData)
		dashboard.POST("/metadata", s.GetMetadata)
		dashboard.POST("/rellm", s.RequestLLMAnalysis)
		dashboard.POST("/addjob", s.UIAddJob)
		dashboard.DELETE("/deljob", s.UIDeleteJob)
		dashboard.GET("/settings", s.GetSettings)
		dashboard.POST("/settings", s.SaveSettings)
	}
}

func (s *Server) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) RunnerConnect(c *gin.Context) {
	err := s.WSHandler.Convert(c, websocketID(uuid.New().String()))
	if err != nil {
		log.Errorf("unable to upgrade to websocket: %v", err)
	}
}

// ------------ UI Dashboard Endpoints ------------ //

func (s *Server) UIDashboard(c *gin.Context) {
	response := types.DashboardResponse{
		RunnersOnlineCnt: s.WSHandler.rm.getRunnerCount(),
	}
	c.JSON(http.StatusOK, response)
}

func (s *Server) UIRunners(c *gin.Context) {
	response := types.RunnersResponse{
		RunnersOnlineInfo: *s.WSHandler.rm.getAllRunners(),
	}
	c.JSON(http.StatusOK, response)
}

func (s *Server) GetJobs(c *gin.Context) {
	jobs, err := s.WSHandler.sql.RetrieveAllJobs()
	if err != nil {
		log.Errorf("unable to retrieve all jobs: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var resp []types.JobResponse

	for _, job := range *jobs {
		resp = append(resp, types.JobResponse{
			JobID:                job.JobID,
			Name:                 job.Name,
			SHA256:               job.SHA256,
			RunCommand:           job.RunCommand,
			RunCommandArgs:       job.RunCommandArgs,
			FileArgs:             job.FileArgs,
			Arch:                 job.Arch,
			LLMResponse:          string(job.LLMResponse),
			RunDuration:          job.RunDuration,
			SaveCMDOutput:        job.SaveCMDOutput,
			Status:               job.Status,
			CreatedTime:          job.CreatedTime,
			SystemPromptOverride: job.SystemPromptOverride,
		})
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) GetCMDData(c *gin.Context) {
	var uiJobID types.UIRequestWithUUID

	if err := c.ShouldBindJSON(&uiJobID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jobID, err := uuid.Parse(uiJobID.JobID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cmdData, err := s.WSHandler.sql.RetrieveStdoutData(jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var resp types.UICMDDataResponse
	resp.JobID = jobID

	if cmdData != nil {
		resp.CMDData = string(cmdData.RawData)
		c.JSON(http.StatusOK, resp)
		return
	}

	resp.CMDData = "CMD Data Not Available"

	c.JSON(http.StatusOK, resp)
}

func (s *Server) GetMetadata(c *gin.Context) {
	var uiJobID types.UIRequestWithUUID

	if err := c.ShouldBindJSON(&uiJobID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jobID, err := uuid.Parse(uiJobID.JobID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	metadata, err := s.WSHandler.sql.RetrieveJobMetadata(jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for key, event := range metadata.SSLMap {
		metadata.SSLMap[key] = strings.ReplaceAll(event, "\u0000", "")
	}

	c.JSON(http.StatusOK, metadata)
}

func (s *Server) GetSettings(c *gin.Context) {
	settings, err := s.WSHandler.sql.GetSystemSetting()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, settings)
}

func (s *Server) SaveSettings(c *gin.Context) {
	var tempSettings types.SystemSettings

	if err := c.ShouldBindJSON(&tempSettings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if modelCtxLen, exists := types.SupportedLLMModelsMap[tempSettings.Model]; exists {
		if tempSettings.CtxLen > modelCtxLen {
			c.JSON(http.StatusBadRequest, gin.H{"error": "model context length exceeded"})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "model not supported"})
		return
	}

	if tempSettings.Temperature < 0 || tempSettings.Temperature > 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "temperature must be between 0 and 2"})
		return
	}

	if tempSettings.TopK < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "top_k must be greater than 0"})
		return
	}

	if tempSettings.TopP < 0 || tempSettings.TopP > 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "top_p must be between 0 and 1"})
		return
	}

	if tempSettings.RepeatPen < -2 || tempSettings.RepeatPen > 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "repeat penalty must be between -2 and 2"})
		return
	}

	if tempSettings.SystemPrompt == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "LLM system prompt cannot be empty"})
		return
	}

	if err := s.WSHandler.sql.SaveSystemSetting(tempSettings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, "Saved System Settings")
}

func (s *Server) RequestLLMAnalysis(c *gin.Context) {
	var uiJobID types.UIRequestWithUUID

	if err := c.ShouldBindJSON(&uiJobID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jobID, err := uuid.Parse(uiJobID.JobID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mainJobData, err := s.WSHandler.sql.RetrieveJobData(jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if len(mainJobData.RawData) <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no ebpf data for llm"})
		return
	}

	sysSettings, err := s.WSHandler.sql.GetSystemSetting()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	numTokens := len(s.WSHandler.llm.Tke.Encode(string(mainJobData.RawData), nil, nil))
	if numTokens > 10000 {
		log.Warnf("Warning ---> %d tokens received, LLM may lose context", numTokens)
	}

	if numTokens >= (sysSettings.CtxLen - 100) {
		log.Warnf("WARNING ---> %d tokens is not allowed - over context length", numTokens)
		c.JSON(http.StatusBadRequest, gin.H{"error": "context length not allowed"})
		s.WSHandler.sql.UpdateJobStatus(jobID, types.Failed)
		return
	}

	systemPromptOverride, err := s.WSHandler.sql.RetrieveJobInfoPromptOverride(jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, "Requesting, this may take a while")

	go func() {
		log.Infof("Requesting LLM Analysis for job: %s.......... Tokens: %d\n", jobID, numTokens)
		llmResponse, err := SendLLMRequest(*s.WSHandler.llm.Client, sysSettings.Model, mainJobData.RawData, sysSettings.TopK, sysSettings.TopP, sysSettings.Temperature, sysSettings.RepeatPen, sysSettings.CtxLen, *systemPromptOverride)
		if err != nil {
			s.WSHandler.sql.UpdateJobStatus(jobID, types.LLMTimeout)
			log.Warnf("LLM response error for job: %s err: %v", jobID, err)
			return
		}

		err = s.WSHandler.sql.UpdateJobInfoLLMResponse(jobID, llmResponse)
		if err != nil {
			log.Warnf("unable to update llm response for job: %d err: %v", jobID, err)
			return
		}

		s.WSHandler.sql.UpdateJobStatus(jobID, types.Success)

		log.Infof("Received LLM Analysis for job: %s", jobID)
	}()

}

func (s *Server) UIAddJob(c *gin.Context) {
	var uiJob types.UIAddJob

	if err := c.ShouldBindJSON(&uiJob); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	timeNow := time.Now().UTC()

	if uiJob.Name == "" {
		uiJob.Name = timeNow.Format("15:04:05") + " UTC"
	}

	if uiJob.RunDuration < 2 || uiJob.RunDuration > 90 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "RunDuration has to been between 2 and 90 seconds"})
		return
	}

	if uiJob.Arch != "amd64" && uiJob.Arch != "arm64" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only amd64 and arm64 is currently supported"})
		return
	}

	var runCommandArgs []string
	if uiJob.RunCommand {
		runCommandArgs = append(runCommandArgs, addShell...)
		runCommandArgs = append(runCommandArgs, uiJob.RunCommandArgs)
	}

	job := types.MalwareJob{
		JobID:          uuid.New(),
		KeepAlive:      uiJob.KeepAlive,
		RunDuration:    uiJob.RunDuration,
		RunCommand:     uiJob.RunCommand,
		RunCommandArgs: runCommandArgs,
		FileArgs:       splitArgs(uiJob.FileArgs),
		SaveCMDOutput:  uiJob.SaveCMDOutput,
		RunCommandEL:   splitArgs(uiJob.BinExclusions),
	}

	if !job.RunCommand {
		fileBytes, err := base64.StdEncoding.DecodeString(uiJob.MalwareFile)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid file data: %v", err)})
			return
		}
		if len(fileBytes) <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file"})
			return
		}
		job.MalwareFile = fileBytes
	}

	log.Printf("JobID: %s, KeepAlive: %v, RunDuration: %d, RunCommand: %v, RunCArgs: %s, FileArgs: %s, Save CMD: %v", job.JobID, job.KeepAlive, job.RunDuration, job.RunCommand, job.RunCommandArgs, job.FileArgs, job.SaveCMDOutput)

	dbJob := types.JobInfo{
		JobID:                job.JobID,
		Name:                 uiJob.Name,
		RunCommand:           job.RunCommand,
		RunCommandArgs:       job.RunCommandArgs,
		FileArgs:             job.FileArgs,
		Arch:                 uiJob.Arch,
		RunDuration:          job.RunDuration,
		SaveCMDOutput:        job.SaveCMDOutput,
		CreatedTime:          timeNow,
		Status:               types.Pending,
		SystemPromptOverride: uiJob.SystemPromptOverride,
	}

	//see if runner is availabe for job
	runnerId, available := s.WSHandler.rm.checkOutRunner(uiJob.Arch)
	if !available {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("runner for arch: %s is not online", uiJob.Arch)}) //TODO decide if job should still be accepted if runner is not availble
		return
	}

	if !job.RunCommand {
		h := sha256.New()
		h.Write(job.MalwareFile)
		dbJob.SHA256 = hex.EncodeToString(h.Sum(nil))
	}

	if err := s.WSHandler.sql.InsertJobInfo(dbJob); err != nil { //TODO decide if malware bytes should be stored (in case runner is offline)
		log.Errorf("unable to insert job info to db: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("insert job into db: %s", err)})
		return
	}

	go s.startMalwareJob(job, runnerId) //start in goroutine to prevent http request timeout for large malware files uploading to runner

	c.JSON(http.StatusOK, "Success")
}

func (s *Server) UIDeleteJob(c *gin.Context) {
	var uiJobID types.UIRequestWithUUID

	if err := c.ShouldBindJSON(&uiJobID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jobID, err := uuid.Parse(uiJobID.JobID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err = s.WSHandler.sql.DeleteJobByID(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, "deleted_job")
}

func splitArgs(stringArgs string) []string {
	var regOutput []string
	var output []string

	re := regexp.MustCompile(`[^\s"]+|"([^"]*)"`)
	regOutput = re.FindAllString(stringArgs, -1)

	for _, field := range regOutput { //to remove extra quotes
		if strings.HasPrefix(field, `"`) && strings.HasSuffix(field, `"`) {
			field = strings.Trim(field, `"`)
		}
		output = append(output, field)
		log.Infof("Appending %s", field)
	}

	return output
}
