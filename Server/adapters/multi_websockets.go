package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"kairos-server/types"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type (
	MultiWSHandler struct {
		websockets map[websocketID]*Websocket
		multiMu    *sync.Mutex
		rm         RMI
		sql        SQL
		llm        *LLM
	}

	Websocket struct {
		conn   *websocket.Conn
		mu     *sync.Mutex
		closed bool
	}

	websocketID string
	MultiWSH    interface {
		Convert(*gin.Context, websocketID) error
		SendMessage(context.Context, websocketID, []byte) error
		Disconnect(websocketID) error
	}
)

func SetupMultiWSHandler(rm RMI, sql SQL, llm *LLM) *MultiWSHandler {
	return &MultiWSHandler{
		websockets: make(map[websocketID]*Websocket),
		multiMu:    &sync.Mutex{},
		rm:         rm,
		sql:        sql,
		llm:        llm,
	}
}

func (w *MultiWSHandler) Convert(ctx *gin.Context, id websocketID) error {
	conn, err := websocket.Accept(ctx.Writer, ctx.Request, nil)
	if err != nil {
		return fmt.Errorf("unable to convert conn to webssocket: %s", err)
	}

	conn.SetReadLimit(250000000) //250mb

	w.addWebsocket(id, &Websocket{
		conn: conn,
		mu:   &sync.Mutex{},
	})

	go w.pingHeartbeat(ctx, id)

	go w.listenToRunnerMessages(ctx, id, ctx.ClientIP())

	return nil
}

func (w *MultiWSHandler) SendMessage(ctx context.Context, id websocketID, msg []byte) error {
	ws := w.getWebsocket(id)
	if ws == nil {
		return fmt.Errorf("unable to find websocket: %s", id)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(30*time.Second))
	defer cancel()
	if err := ws.conn.Write(timeoutCtx, websocket.MessageBinary, msg); err != nil {
		w.rm.deleteRunner(id)
		w.rm.manualDeleteRunnerReady(id)
		ws.closed = true
		w.addWebsocket(id, ws) //re-add ws with closed so disconnect does not fail
		return err
	}
	return nil
}

func (w *MultiWSHandler) readMessage(id websocketID) ([]byte, error) {
	ws := w.getWebsocket(id)
	if ws == nil {
		return nil, fmt.Errorf("unable to find websocket: %s", id)
	}

	ws.mu.Lock()
	defer ws.mu.Unlock()

	readCtx := context.Background()

	_, message, err := ws.conn.Read(readCtx)
	if err != nil {
		w.rm.deleteRunner(id)
		w.rm.manualDeleteRunnerReady(id)
		ws.closed = true
		w.addWebsocket(id, ws)
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil, nil
		}
		return nil, err
	}
	return message, err
}

func (w *MultiWSHandler) Disconnect(id websocketID) error {
	ws := w.getWebsocket(id)
	if ws == nil {
		return fmt.Errorf("unable to find websocket: %s", id)
	}
	defer w.deleteWebsocket(id)
	if ws.closed {
		return nil
	}
	return ws.conn.Close(websocket.StatusNormalClosure, "")
}

func (w *MultiWSHandler) pingHeartbeat(ctx context.Context, id websocketID) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ws := w.getWebsocket(id)
			if ws == nil || ws.closed {
				return
			}
			if err := ws.conn.Ping(ctx); err != nil {
				log.Errorf("unable to ping: %s : %v", id, err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (w *MultiWSHandler) addWebsocket(id websocketID, ws *Websocket) {
	w.multiMu.Lock()
	w.websockets[id] = ws
	w.multiMu.Unlock()
}

func (w *MultiWSHandler) getWebsocket(id websocketID) *Websocket {
	w.multiMu.Lock()
	defer w.multiMu.Unlock()
	return w.websockets[id]
}

func (w *MultiWSHandler) deleteWebsocket(id websocketID) {
	w.multiMu.Lock()
	delete(w.websockets, id)
	w.multiMu.Unlock()
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
