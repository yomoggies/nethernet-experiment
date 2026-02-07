package main

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/yomoggies/nethernet-jsonrpc/minecraft/service"
)

func discovery(t testing.TB) *service.Discovery {
	d, err := service.Discover(service.ApplicationTypeMinecraftPE, "1.21.132")
	if err != nil {
		t.Fatalf("error discovering endpoints for network services: %s", err)
	}
	return d
}

type nnNetwork struct {
	Signaling nethernet.Signaling
	log       *slog.Logger
}

func (n nnNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	var d nethernet.Dialer
	return d.DialContext(ctx, address, n.Signaling)
}

func (n nnNetwork) PingContext(ctx context.Context, address string) ([]byte, error) {
	return nil, nil
}

func (n nnNetwork) Listen(string) (minecraft.NetworkListener, error) {
	var cfg nethernet.ListenConfig
	return cfg.Listen(n.Signaling)
}
