package adapters

import (
	"context"
	"kairos-server/types"

	log "github.com/sirupsen/logrus"
)

func (s *Server) startMalwareJob(job types.MalwareJob, id websocketID) {
	runnerJobMsg, err := WSMarshalObject(job, types.MalwareJobMsg)
	if err != nil {
		log.Errorf("unable to marshal malware job for runner: %v", err)
		return
	}
	ctx := context.Background()
	if err = s.WSHandler.SendMessage(ctx, id, runnerJobMsg); err != nil {
		log.Errorf("unable to send malware job to runner: %v", err) //TODO figure out a way to display warning to user
		return
	}
	s.WSHandler.sql.UpdateJobStatus(job.JobID, types.Running)
}
