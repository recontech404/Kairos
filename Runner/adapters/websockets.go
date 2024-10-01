package adapters

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"kairos-runner/types"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	reconnectTryLimit = 10
	sendRetryLimit    = 4
)

type (
	WSHandler struct {
		conn     *websocket.Conn
		readMu   *sync.Mutex
		closedMu *sync.Mutex
		closed   bool
		ConnUrl  string
		ConnTLS  bool

		WS interface {
			Connect(context.Context, string, bool) error
			SendMessage(context.Context, []byte) error
			ReadMessage(context.Context) ([]byte, error)
			Disconnect() error
		}
	}

	WSConnDetails struct {
		Address       string
		Port          int
		SkipTLSVerify bool
	}
)

var baseWait = 5 //5 seconds

func SetupWebsocket(ctx context.Context, wsc WSConnDetails) *WSHandler {
	w := WSHandler{
		readMu:   &sync.Mutex{},
		closedMu: &sync.Mutex{},
	}

	w.ConnUrl = fmt.Sprintf("ws://%s:%d/ws", wsc.Address, wsc.Port)
	w.ConnTLS = wsc.SkipTLSVerify

	err := w.Connect(ctx)
	if err != nil {
		log.Fatalf("%v", err)
	}

	return &w
}

func (w *WSHandler) Connect(ctx context.Context) error {
	w.closedMu.Lock()
	defer w.closedMu.Unlock()
	connAttempts := 0
connect:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if conn, _, err := websocket.Dial(ctx, w.ConnUrl, &websocket.DialOptions{
				HTTPClient: &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: w.ConnTLS,
						},
					},
				},
			}); err != nil {
				if connAttempts < reconnectTryLimit {
					log.Warnf("dial: %s attempt failed - current try %d", w.ConnUrl, connAttempts)
					connAttempts++
					log.Warnf("waiting %d seconds before trying again", baseWait)
					time.Sleep(time.Duration(baseWait) * time.Second)
					baseWait += 5 //add 5 seconds every time
				} else {
					log.Errorf("unable to dial: %s :%v", w.ConnUrl, err)
					return fmt.Errorf("unable to dial %s: %s", w.ConnUrl, err)
				}
			} else {
				w.conn = conn
				w.closed = false
				log.Info("Connection to server established")
				go w.sendRunnerInfo(ctx)
				baseWait = 5 //reset wait
				break connect
			}
		}
	}

	w.conn.SetReadLimit(250000000) //250mb - max file download

	return nil
}

func (w *WSHandler) ConnClosed() bool {
	w.closedMu.Lock()
	defer w.closedMu.Unlock()
	return w.closed
}

func (w *WSHandler) SendMessage(ctx context.Context, msg []byte) error { //NOTE: re-connect should be handled by read logic
	sendAttempt := 1

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(30*time.Second))
	defer cancel()

send:
	for {
		select {
		case <-ctx.Done():
			log.Warnf("context cancelled while sending ws message")
			break send
		default:
			if !w.ConnClosed() {
				if err := w.conn.Write(timeoutCtx, websocket.MessageBinary, msg); err != nil {
					if sendAttempt <= sendRetryLimit {
						log.Warnf("failure to send ws message - attempt: %d err: %v\n", sendAttempt, err)
						time.Sleep((time.Duration(sendAttempt * baseWait)) * time.Second)
						sendAttempt++
					} else {
						w.closedMu.Lock()
						w.closed = true
						w.closedMu.Unlock()
						return err
					}
				} else {
					break send
				}
			}
		}
	}
	return nil
}

func (w *WSHandler) ReadMessage() ([]byte, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	readCtx := context.Background()

	_, message, err := w.conn.Read(readCtx)
	if err != nil {
		w.closedMu.Lock()
		w.closed = true
		w.closedMu.Unlock()
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil, nil
		}
		return nil, err
	}

	return message, err
}

func (w *WSHandler) Disconnect() error {
	if w.closed {
		return nil
	}
	return w.conn.Close(websocket.StatusNormalClosure, "")
}

func WSMarshalObject(obj interface{}, dataType types.WSDataType) ([]byte, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal: %v", err)
	}
	rawDataWithType := types.WSData{
		Type: dataType,
		Data: data,
	}

	dataWithType, err := json.Marshal(rawDataWithType)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal with type: %v", err)
	}

	return dataWithType, nil
}

func verifyRunnerBTFSupport() bool {
	cmd := exec.Command("sysctl", "-n", "net.core.bpf_jit_enable")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	if string(output) != "1\n" {
		return false
	}
	return true
}

func (w *WSHandler) sendRunnerInfo(ctx context.Context) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	ebpfSupport := verifyRunnerBTFSupport()
	var runnerData = types.RunnerData{
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		EBPFSupport: ebpfSupport,
	}

	runnerInfoMsg, err := WSMarshalObject(runnerData, types.RunnerInfoMsg)
	if err != nil {
		log.Fatalf("ebpf support check failed: %v", err)
	}
	err = w.SendMessage(ctx, runnerInfoMsg)
	if err != nil {
		log.Fatalf("unable to send epbf support check msg: %v", err)
	}
}
