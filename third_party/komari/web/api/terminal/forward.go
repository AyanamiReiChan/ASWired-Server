package terminal

import (
	"errors"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/pkg/aswired"
)

func ForwardTerminal(id string) {
	session, exists := TerminalSessions[id]

	if !exists || session == nil || session.Agent == nil || session.Browser == nil {
		return
	}
	auditlog.Log(session.RequesterIp, session.UserUUID, "established, terminal id:"+id, "terminal")
	established_time := time.Now()
	errChan := make(chan error, 3)
	done := make(chan struct{})
	defer close(done)
	checkIdentity := func() error {
		if session.IdentitySession == "" {
			return nil
		}
		identity, err := aswired.Session(session.IdentitySession)
		if err != nil || identity.ID != session.UserUUID {
			return errors.New("terminal login expired")
		}
		return nil
	}
	if session.IdentitySession != "" {
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				if err := checkIdentity(); err != nil {
					errChan <- err
					return
				}
				select {
				case <-done:
					return
				case <-ticker.C:
				}
			}
		}()
	}

	go func() {
		for {
			messageType, data, err := session.Browser.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			if err := checkIdentity(); err != nil {
				errChan <- err
				return
			}
			if messageType == websocket.TextMessage {
				if session.Agent != nil && len(data) > 0 && data[0] == '{' {
					err = session.Agent.WriteMessage(websocket.TextMessage, data)
				} else if session.Agent != nil {
					err = session.Agent.WriteMessage(websocket.BinaryMessage, data)
				}
			} else if session.Agent != nil {
				// 二进制消息，原样传递
				err = session.Agent.WriteMessage(websocket.BinaryMessage, data)
			}

			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			_, data, err := session.Agent.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if session.Browser != nil {
				err = session.Browser.WriteMessage(websocket.BinaryMessage, data)
				if err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	// 等待错误或主动关闭
	<-errChan
	// 关闭连接
	if session.Agent != nil {
		session.Agent.Close()
	}
	if session.Browser != nil {
		session.Browser.Close()
	}
	disconnect_time := time.Now()
	auditlog.Log(session.RequesterIp, session.UserUUID, "disconnected, terminal id:"+id+", duration:"+disconnect_time.Sub(established_time).String(), "terminal")
	TerminalSessionsMutex.Lock()
	delete(TerminalSessions, id)
	TerminalSessionsMutex.Unlock()
}
