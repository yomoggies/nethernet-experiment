package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi"
)

func playfab(t testing.TB, c *xsapi.Client) string {
	requestURL := playFabEndpoint.JoinPath("Client/LoginWithXbox")
	token, _, err := c.TokenAndSignature(t.Context(), requestURL)
	if err != nil {
		t.Fatalf("error requesting XSTS token for PlayFab: %s", err)
	}
	buf := &bytes.Buffer{}
	defer buf.Reset()
	if err := json.NewEncoder(buf).Encode(map[string]any{
		"CreateAccount": true,
		"XboxToken":     token.String(),
		"TitleId":       playFabTitleID,
	}); err != nil {
		t.Fatalf("login playfab: error encoding request body: %s", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), buf)
	if err != nil {
		t.Fatalf("login playfab: error making request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "libHttpClient/1.0.0.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %s", req.Method, requestURL, resp.Status)
	}
	b, _ := io.ReadAll(resp.Body)
	// fmt.Println(string(b))
	var m struct {
		Data *struct {
			SessionTicket string
			NewlyCreated  bool
			PlayFabID     string `json:"PlayFabId"`
		}
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&m); err != nil {
		t.Fatalf("error decoding playfab session identity: %s", err)
	}
	if m.Data == nil || m.Data.SessionTicket == "" {
		t.Fatalf("invalid playfab login response: %#v", m)
	}
	return m.Data.SessionTicket
}

const playFabTitleID = "20CA2"

var (
	playFabEndpoint = &url.URL{
		Scheme: "https",
		Host:   strings.ToLower(playFabTitleID) + ".playfabapi.com",
	}
)
