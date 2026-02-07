package minecraft

import (
	"context"
	"crypto/ecdsa"
)

// MultiplayerTokenSource supplies a multiplayer token issued by the Minecraft authorization
// service, which is newly introduced in 1.21.100.
//
// The token is key-bound (it includes the client's public key in the 'cpk' claim), so callers should
// expect to request it per connection key.
type MultiplayerTokenSource interface {
	// MultiplayerToken issues a JWT token to be used for OpenID authentication with
	// multiplayer servers. The token must contain the public key in the 'cpk' claim in
	// order for the server to verify client data with the same key.
	MultiplayerToken(ctx context.Context, key *ecdsa.PublicKey) (jwt string, err error)
}
