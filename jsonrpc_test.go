package main

import (
	"context"
	"crypto/ecdsa"
	rand2 "crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-xsapi"
	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft"
	auth2 "github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/nethernet-jsonrpc/minecraft/service"
	"golang.org/x/oauth2"
)

func deviceID() string {
	b := make([]byte, 16)
	_, _ = rand2.Reader.Read(b)
	return hex.EncodeToString(b)
}

func TestJSONRPC(t *testing.T) {
	_, src := auth(t)
	client, err := xsapi.NewClient(src, nil)
	if err != nil {
		t.Fatalf("error creating API client: %s", err)
	}
	// TODO: Implement Client.Close()

	t.Logf("logged in as %s (%s)", client.UserInfo().GamerTag, client.UserInfo().XUID)
	sessionTicket := playfab(t, client)
	d := discovery(t)
	mct, err := d.ServiceEnvironments.Authorization.Environment.Token(context.Background(), service.TokenConfig{
		User: service.UserConfig{
			TokenType: service.TokenTypePlayFab,
			Token:     sessionTicket,
		},
		Device: service.DeviceConfig{
			ID: deviceID(),
		},
	})
	if err != nil {
		t.Fatalf("error requesting Minecraft token: %s", err)
	}

	u, err := url.Parse(d.ServiceEnvironments.Signaling.Environment.ServiceURI)
	if err != nil {
		t.Fatalf("error parsing %q as URL: %s", d.ServiceEnvironments.Signaling.Environment.ServiceURI, err)
	}
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second*15)
		opts        = &websocket.DialOptions{
			HTTPHeader: make(http.Header),
		}
	)
	defer cancel()
	opts.HTTPHeader.Set("Authorization", mct.AuthorizationHeader)
	opts.HTTPHeader.Set("User-Agent", "libHttpClient/1.0.0.0")
	// TODO: session-id and request-id

	conn, _, err := websocket.Dial(ctx, u.JoinPath("/ws/v1.0/messaging/connect").String(), opts)
	if err != nil {
		t.Fatalf("error connecting to signaling service: %s", err)
	}
	/*t.Cleanup(func() {
		if err := conn.Close(websocket.StatusNormalClosure, ""); err != nil {
			t.Fatalf("error closing websocket connection: %s", err)
		}
	})*/
	networkID, messagingID := rand.Uint64(), claimMessagingID(t, mct)
	// session := publishSession(t, client, networkID, messagingID)
	t.Log(messagingID)

	// doStuff(t, session, conn, networkID, messagingID)
	// dialConn(t, conn, networkID, messagingID)
	dialRealms(t, client, mct, d.ServiceEnvironments.Authorization.Environment, conn, networkID, messagingID)
}

const remoteMessagingID = "4"

func dialRealms(t testing.TB, client *xsapi.Client, mct *service.Token, env *service.AuthorizationEnvironment, conn *websocket.Conn, networkID uint64, messagingID uuid.UUID) {
	signaling := newJSONRPCSignaling(t, conn, messagingID, strconv.FormatUint(networkID, 10))
	minecraft.RegisterNetwork("nethernet", func(l *slog.Logger) minecraft.Network {
		return &nnNetwork{Signaling: signaling}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()

	u, err := url.Parse("https://multiplayer.minecraft.net/authentication")
	if err != nil {
		t.Fatalf("error parsing minecraft login chain URL: %s", err)
	}
	token, _, err := client.TokenAndSignature(ctx, u)
	if err != nil {
		t.Fatalf("error retrieving XSTS token for %s: %s", u, err)
	}
	xblToken := new(auth2.XBLToken)
	xblToken.AuthorizationToken.Token = token.Token
	xblToken.AuthorizationToken.NotAfter = token.NotAfter
	xblToken.AuthorizationToken.IssueInstant = token.IssueInstant
	xblToken.AuthorizationToken.DisplayClaims.UserInfo = []struct {
		GamerTag string `json:"gtg"`
		XUID     string `json:"xid"`
		UserHash string `json:"uhs"`
	}{
		{UserHash: token.UserInfo().UserHash},
	}
	c, err := minecraft.Dialer{
		ErrorLog: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		TokenSource: &multiplayerTokenSource{
			token:       mct,
			TokenSource: nil, // This is never used so we intentionally set nil
			Environment: env,
		},
		XBLToken: xblToken,
	}.DialContext(ctx, "nethernet", remoteMessagingID)
	if err != nil {
		t.Fatalf("error connecting to Realms: %s", err)
	}
	defer c.Close()

	for {
		pk, err := c.ReadPacket()
		if err != nil {
			t.Fatalf("error reading packet: %s", err)
		}
		t.Logf("%T", pk)
	}
}

type multiplayerTokenSource struct {
	token       *service.Token
	Environment *service.AuthorizationEnvironment
	oauth2.TokenSource
}

func (s *multiplayerTokenSource) MultiplayerToken(ctx context.Context, publicKey *ecdsa.PublicKey) (string, error) {
	return s.Environment.MultiplayerToken(ctx, &staticServiceTokenSource{s.token}, publicKey)
}

type staticServiceTokenSource struct{ token *service.Token }

func (s *staticServiceTokenSource) Token() (*service.Token, error) {
	return s.token, nil
}

func dialConn(t testing.TB, conn *websocket.Conn, networkID uint64, messagingID uuid.UUID) {
	signaling := newJSONRPCSignaling(t, conn, messagingID, strconv.FormatUint(networkID, 10))
	c, err := nethernet.Dialer{
		Log: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		API: webrtc.NewAPI(func(api *webrtc.API) {
			factory := logging.NewDefaultLoggerFactory()
			factory.DefaultLogLevel = logging.LogLevelDebug
			webrtc.WithSettingEngine(webrtc.SettingEngine{
				LoggerFactory: factory,
			})(api)
		}),
	}.DialContext(t.Context(), remoteMessagingID, signaling)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	t.Logf("%s, %s", c.RemoteAddr(), c.LocalAddr())
}

func claimMessagingID(t testing.TB, mct *service.Token) uuid.UUID {
	token, err := jwt.ParseSigned(strings.TrimPrefix(mct.AuthorizationHeader, "MCToken "), []jose.SignatureAlgorithm{
		jose.RS256,
	})
	if err != nil {
		t.Fatalf("error parsing service token: %s", err)
	}
	var claims struct {
		jwt.Claims
		PlayerMessagingID uuid.UUID `json:"pmid"`
	}
	// actually the key is under the OpenID configuration, but we won't verify it for now
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("error extracting JWT claims: %s", err)
	}
	if err := claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		t.Fatalf("error validating claims: %s", err)
	}
	return claims.PlayerMessagingID
}

func doStuff(t testing.TB, s *mpsd.Session, conn *websocket.Conn, networkID uint64, messagingID uuid.UUID) {
	signaling := newJSONRPCSignaling(t, conn, messagingID, strconv.FormatUint(networkID, 10))
	l, err := nethernet.ListenConfig{
		Log: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		API: webrtc.NewAPI(func(api *webrtc.API) {
			factory := logging.NewDefaultLoggerFactory()
			// factory.DefaultLogLevel = logging.LogLevelDebug
			webrtc.WithSettingEngine(webrtc.SettingEngine{
				LoggerFactory: factory,
			})(api)
		}),
	}.Listen(signaling)
	if err != nil {
		t.Fatalf("error listening on NetherNet: %s", err)
	}
	time.AfterFunc(time.Minute*1, func() {
		if err := l.Close(); err != nil {
			t.Errorf("error closing NetherNet listener: %s", err)
		}
	})
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Fatalf("error closing NetherNet listener: %s", err)
		}
	})

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.Fatalf("error accepting connection: %s", err)
		}
		t.Logf("Accepted: %s", c.RemoteAddr())

		time.AfterFunc(time.Second*5, func() {
			if err := c.Close(); err != nil {
				t.Fatalf("error closing connection: %s", err)
			}
		})
	}
}

type websocketChannel struct{ *websocket.Conn }

func (ch *websocketChannel) Send(b []byte) error {
	return ch.Write(context.Background(), websocket.MessageText, b)
}

func (ch *websocketChannel) Recv() ([]byte, error) {
	_, msg, err := ch.Read(context.Background())
	return msg, err
}

func (ch *websocketChannel) Close() error {
	return ch.Conn.Close(websocket.StatusNormalClosure, "")
}
