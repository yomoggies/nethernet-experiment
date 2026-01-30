module github.com/yomoggies/nethernet-jsonrpc

go 1.25.5

require (
	github.com/coder/websocket v1.8.12
	github.com/coreos/go-oidc/v3 v3.17.0
	github.com/creachadair/jrpc2 v1.3.4
	github.com/df-mc/go-nethernet v0.0.0-20260106140245-e6a86cbce687
	github.com/df-mc/go-xsapi v1.0.1
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/google/uuid v1.6.0
	github.com/pion/logging v0.2.4
	github.com/pion/webrtc/v4 v4.1.8
	golang.org/x/oauth2 v0.34.0
	golang.org/x/text v0.33.0
)

require (
	github.com/creachadair/mds v0.25.13 // indirect
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v3 v3.0.9 // indirect
	github.com/pion/ice/v4 v4.1.0 // indirect
	github.com/pion/interceptor v0.1.42 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.8.26 // indirect
	github.com/pion/sctp v1.8.41 // indirect
	github.com/pion/sdp/v3 v3.0.16 // indirect
	github.com/pion/srtp/v3 v3.0.9 // indirect
	github.com/pion/stun/v3 v3.0.2 // indirect
	github.com/pion/transport/v3 v3.1.1 // indirect
	github.com/pion/turn/v4 v4.1.3 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace (
	github.com/df-mc/go-nethernet => github.com/lactyy/go-nethernet v1.0.0-alpha.2.0.20260107091143-efab6f57a8d4
	github.com/df-mc/go-xsapi => github.com/lactyy/go-xsapi v0.0.0-20260129205551-ec7c13aed847
)
