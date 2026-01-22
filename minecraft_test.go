package main

import (
	"testing"

	"github.com/yomoggies/nethernet-jsonrpc/minecraft/service"
)

func discovery(t testing.TB) *service.Discovery {
	d, err := service.Discover(service.ApplicationTypeMinecraftPE, "1.21.132")
	if err != nil {
		t.Fatalf("error discovering endpoints for network services: %s", err)
	}
	return d
}
