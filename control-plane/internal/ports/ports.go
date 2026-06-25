// Package ports declares the interfaces the control plane depends on. Real
// adapters (edge API, cloud SDKs) implement these; unit tests use fakes.
package ports

import (
	"context"

	"github.com/tessera/control-plane/internal/domain"
)

// SCIMClient pushes provisioning changes to the edge SCIM service provider.
type SCIMClient interface {
	PushUser(ctx context.Context, u domain.Identity) error
	SetActive(ctx context.Context, userID string, active bool) error
	ListUsers(ctx context.Context) ([]domain.Identity, error)
}

// StateStore reads/writes lifecycle state to D1/DO via the edge API.
type StateStore interface {
	GetIdentity(ctx context.Context, id string) (domain.Identity, error)
	PutIdentity(ctx context.Context, i domain.Identity) error
	ListByState(ctx context.Context, s domain.LifecycleState) ([]domain.Identity, error)
}

// Revoker is the Leaver-saga port (implemented in package offboard). It is the
// union of one SCIM disable + RFC 7009 + Back-Channel Logout + API-key revoke,
// each step capability-checked per app.
type Revoker interface {
	DisableAccount(ctx context.Context, app, userID string) error
	RevokeOAuthGrant(ctx context.Context, app, userID string) error  // RFC 7009
	TerminateSessions(ctx context.Context, app, userID string) error // Back-Channel Logout
	RevokeAPIKeys(ctx context.Context, app, userID string) error
	// Supports reports which saga steps an app implements; absent steps require
	// a compensating control to be logged.
	Supports(app string) AppCapabilities
}

// AppCapabilities declares which offboarding primitives an app exposes.
type AppCapabilities struct {
	OAuthRevocation   bool // RFC 7009
	BackChannelLogout bool // OIDC Back-Channel Logout
	APIKeyRevocation  bool
}
