package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi"
	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/df-mc/go-xsapi/xal"
	"github.com/df-mc/go-xsapi/xal/sisu"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func auth(t testing.TB) (oauth2.TokenSource, *sisu.Session) {
	msa := readToken(t, tokenPath)
	src := oauth2.StaticTokenSource(msa)
	sc := &sisu.SessionConfig{}
	sc.Snapshot = readSnapshot(t, snapshotPath)
	s := MinecraftAndroid.New(src, sc)
	t.Cleanup(func() {
		snapshot := s.Snapshot()
		if snapshot == nil {
			t.Fatalf("Session.Snapshot must return non-nil SessionState")
		}
		writeSnapshot(t, snapshotPath, snapshot)
	})

	return src, s
}

func publishSession(t testing.TB, client *xsapi.Client, networkID uint64, messagingID uuid.UUID) *mpsd.Session {
	// addFriend(t, client, "2535428765332540")

	custom, err := json.Marshal(map[string]any{
		"Joinability":             "joinable_by_friends",
		"hostName":                client.UserInfo().GamerTag,
		"ownerId":                 client.UserInfo().XUID,
		"rakNetGUID":              "",
		"version":                 "1.21.132",
		"levelId":                 "opSQE3ZX5Yc=",
		"worldName":               "マイ ワールド",
		"worldType":               "Creative",
		"protocol":                898,
		"MemberCount":             1,
		"MaxMemberCount":          8,
		"BroadcastSetting":        3,
		"LanGame":                 true,
		"isEditorWorld":           false,
		"isHardcore":              false,
		"TransportLayer":          2,
		"OnlineCrossPlatformGame": true,
		"CrossPlayDisabled":       false,
		"TitleId":                 0,
		"SupportedConnections": []map[string]any{
			{
				"ConnectionType": 7,
				"HostIpAddress":  "",
				"HostPort":       0,
				"NetherNetId":    networkID,
				"PmsgId":         messagingID,
			},
		},
	})
	if err != nil {
		t.Fatalf("error encoding custom properties: %s", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()
	session, err := client.MPSD().Publish(ctx, mpsd.SessionReference{
		ServiceConfigID: serviceConfigID,
		TemplateName:    "MinecraftLobby",
	}, mpsd.PublishConfig{
		CustomProperties: custom,
	})
	if err != nil {
		t.Fatalf("error publishing multiplayer session: %s", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("error closing multiplayer session: %s", err)
		}
	})

	return session
}

func readSnapshot(t testing.TB, path string) *sisu.Snapshot {
	if stat, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if stat.IsDir() {
		t.Fatalf("%q is a directory", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error reading session snapshot: %s", path)
	}
	var s *jsonSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("error decoding session s: %s", err)
	}
	return s.Snapshot
}

func writeSnapshot(t testing.TB, path string, snapshot *sisu.Snapshot) {
	b, err := json.Marshal(&jsonSnapshot{Snapshot: snapshot})
	if err != nil {
		t.Fatalf("error encoding Snapshot: %s", err)
	}
	if err := os.WriteFile(path, b, os.ModePerm); err != nil {
		t.Fatalf("error writing session snapshot to %s: %s", path, err)
	}
	t.Logf("Session.Snapshot: %s", b)
}

type jsonSnapshot struct {
	*sisu.Snapshot
	ProofKey jose.JSONWebKey
}

func (c *jsonSnapshot) MarshalJSON() ([]byte, error) {
	type Alias jsonSnapshot
	a := Alias{
		Snapshot: c.Snapshot,
		ProofKey: jose.JSONWebKey{
			Key:       c.Snapshot.ProofKey,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	return json.Marshal(a)
}

func (c *jsonSnapshot) UnmarshalJSON(b []byte) error {
	type Alias jsonSnapshot
	if err := json.Unmarshal(b, (*Alias)(c)); err != nil {
		return err
	}
	c.Snapshot.ProofKey = c.ProofKey.Key.(*ecdsa.PrivateKey)
	return nil
}

func readToken(t testing.TB, path string) *oauth2.Token {
	if stat, err := os.Stat(path); os.IsNotExist(err) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
		defer cancel()
		da, err := MinecraftAndroid.DeviceAuth(ctx)
		if err != nil {
			t.Fatalf("error requesting device auth code flow: %s", err)
		}
		t.Logf("Sign in to Microsoft Account at %s using the code %s.", da.VerificationURI, da.UserCode)

		ctx, cancel = context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		msa, err := MinecraftAndroid.DeviceAccessToken(ctx, da)
		if err != nil {
			t.Fatalf("error polling access token in device auth code flow: %s", err)
		}
		b, err := json.Marshal(msa)
		if err != nil {
			t.Fatalf("error encoding MSA token: %s", err)
		}
		if err := os.WriteFile(path, b, os.ModePerm); err != nil {
			t.Fatalf("error writing MSA token to %s: %s", path, err)
		}
		return msa
	} else if err != nil {
		t.Fatalf("stat %q: %s", path, err)
	} else if stat.IsDir() {
		t.Fatalf("%q is a directory", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error reading %s: %s", path, err)
	}
	var msa *oauth2.Token
	if err := json.Unmarshal(b, &msa); err != nil {
		t.Fatalf("error decoding MSA token: %s", err)
	}
	if msa == nil || !msa.Valid() {
		t.Fatalf("MSA token is invalid")
	}
	return msa
}

const (
	testdataDir = "testdata"
)

var (
	snapshotPath = filepath.Join(testdataDir, "session.snapshot")
	tokenPath    = filepath.Join(testdataDir, "msa.token")

	MinecraftAndroid = sisu.Config{
		Config: xal.Config{
			Device: xal.Device{
				Type:    xal.DeviceTypeAndroid,
				Version: "13",
			},
			UserAgent: "XAL Android 2025.04.20250326.000",
			TitleID:   1739947436,
		},

		ClientID:    "0000000048183522",
		RedirectURI: "ms-xal-0000000048183522://auth",
		Sandbox:     "RETAIL",
	}

	serviceConfigID = uuid.MustParse("4fc10100-5f7a-4470-899b-280835760c07")
)
