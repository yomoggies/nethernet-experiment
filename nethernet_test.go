package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
)

func newJSONRPCSignaling(t testing.TB, conn *websocket.Conn, messagingID uuid.UUID, networkID string) *jsonrpcSignaling {
	j := &jsonrpcSignaling{
		t: t,

		conn:           conn,
		notifiers:      make(map[int]chan<- *nethernet.Signal),
		networkIDs:     make(map[string]networkIDMapping),
		messagingID:    messagingID,
		localNetworkID: networkID,
	}
	j.client = jrpc2.NewClient(&websocketChannel{conn}, &jrpc2.ClientOptions{
		OnCallback: j.handleCallback,
	})
	return j
}

type jsonrpcSignaling struct {
	t              testing.TB
	conn           *websocket.Conn
	client         *jrpc2.Client
	messagingID    uuid.UUID
	localNetworkID string

	notifiers   map[int]chan<- *nethernet.Signal
	notifyCount int
	notifiersMu sync.Mutex

	credentials     *nethernet.Credentials
	credentialsTime time.Time
	credentialsMu   sync.Mutex

	networkIDs   map[string]networkIDMapping
	networkIDsMu sync.Mutex
}

func (j *jsonrpcSignaling) handleCallback(ctx context.Context, req *jrpc2.Request) (result any, err error) {
	switch req.Method() {
	case "Signaling_ReceiveMessage_v1_0":
		defer func() {
			if err != nil {
				j.t.Error(err)
			}
		}()
		var batch []struct {
			From  uuid.UUID
			Inner string `json:"Message"`
			ID    string `json:"Id"`
		}
		if err := req.UnmarshalParams(&batch); err != nil {
			return nil, fmt.Errorf("handle %q: decode parameters: %w", req.Method(), err)
		}
		for _, msg := range batch {
			var inner *jrpc2.ParsedRequest
			if err := json.Unmarshal([]byte(msg.Inner), &inner); err != nil {
				return nil, fmt.Errorf("handle %q: decode inner message: %w", req.Method(), err)
			}
			if inner == nil {
				return nil, fmt.Errorf("handle %q: invalid batch message in params", req.Method())
			}

			switch inner.Method {
			case "Signaling_WebRtc_v1_0":
				var params struct {
					NetherNetID string `json:"netherNetId"` // ignored, just using their Messaging ID
					Data        string `json:"message"`
				}
				if err := json.Unmarshal(inner.Params, &params); err != nil {
					return nil, fmt.Errorf("handle %q: decode parameters in inner message: %w", req.Method(), err)
				}
				if params.NetherNetID == "" || params.Data == "" {
					return nil, fmt.Errorf("handle %q: invalid inner message", req.Method())
				}

				signal := &nethernet.Signal{NetworkID: msg.From.String()}
				if err := signal.UnmarshalText([]byte(params.Data)); err != nil {
					return nil, fmt.Errorf("handle %q: decode inner message data to signal: %w", req.Method(), err)
				}

				j.notifiersMu.Lock()
				for _, ch := range j.notifiers {
					ch <- signal
				}
				j.notifiersMu.Unlock()

				b, _ := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"method":  "Signaling_DeliveryNotification_V1_0",
					"params": map[string]any{
						"netherNetId": j.localNetworkID,
					},
				})
				resp, err := j.client.Call(ctx, "Signaling_SendClientMessage_v1_0", map[string]any{
					"toPlayerId": msg.From,
					"messageId":  msg.ID,
					"message":    string(b),
				})
				if err != nil {
					return nil, fmt.Errorf("call Signaling_SendClientMessage_v1_0: %w", err)
				}
				if resp.Error() != nil {
					return nil, resp.Error()
				}
				return nil, nil
			case "Signaling_DeliveryNotification_V1_0":
				continue
			default:
				return nil, fmt.Errorf("handle %q: invalid inner message method: %q", req.Method(), inner.Method)
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown JSONRPC method: %q", req.Method())
	}
}

func (j *jsonrpcSignaling) Signal(ctx context.Context, signal *nethernet.Signal) error {
	// j.t.Logf("Signal(%s)", signal)

	// This is half-encoded JSONRPC 2.0 Message, but it isn't exported in the jrpc2 package.
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "Signaling_WebRtc_v1_0",
		"params": map[string]any{
			"netherNetId": j.localNetworkID,
			"message":     signal.String(),
		},
	})
	messagingID := uuid.MustParse(signal.NetworkID)
	resp, err := j.client.Call(ctx, "Signaling_SendClientMessage_v1_0", map[string]any{
		"toPlayerId": messagingID,
		"messageId":  uuid.New(), //< A unique ID associated to each message sent by the client.
		"message":    string(b),
	})
	if err != nil {
		return err
	}
	if resp.Error() != nil {
		return resp.Error()
	}
	return nil
}

func (j *jsonrpcSignaling) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	// j.t.Logf("Notify(%#v)", ch)

	j.notifiersMu.Lock()
	i := j.notifyCount
	j.notifiers[i] = ch
	j.notifyCount++
	j.notifiersMu.Unlock()

	return func() {
		j.notifiersMu.Lock()
		delete(j.notifiers, i)
		close(ch)
		j.notifiersMu.Unlock()
	}
}

func (j *jsonrpcSignaling) Context() context.Context {
	return j.t.Context()
}

func (j *jsonrpcSignaling) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	// j.t.Logf("Credentials(%#v)", ctx)

	j.credentialsMu.Lock()
	defer j.credentialsMu.Unlock()

	if j.credentials != nil {
		exp := j.credentialsTime.Add(time.Second * time.Duration(j.credentials.ExpirationInSeconds))
		if time.Now().Before(exp) {
			return j.credentials, nil
		}
	}

	var credentials *nethernet.Credentials
	if err := j.client.CallResult(ctx, "Signaling_TurnAuth_v1_0", map[string]any{}, &credentials); err != nil {
		return nil, fmt.Errorf("call Signaling_TurnAuth_v1_0: %w", err)
	}
	if credentials == nil || credentials.ExpirationInSeconds == 0 {
		return nil, errors.New("call Signaling_TurnAuth_v1_0: invalid result")
	}
	j.credentials, j.credentialsTime = credentials, time.Now()
	return j.credentials, nil
}

func (j *jsonrpcSignaling) NetworkID() string {
	return j.localNetworkID
}

func (j *jsonrpcSignaling) PongData([]byte) {}

type networkIDMapping struct {
	networkID   string
	messagingID uuid.UUID
	t           time.Time
}
