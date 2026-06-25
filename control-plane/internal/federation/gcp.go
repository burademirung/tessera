package federation

import (
	"context"
	"fmt"
)

// GCPExchangeInput is the STS token-exchange request shape (brief-03 §2).
type GCPExchangeInput struct {
	Audience           string // WIF provider resource URL (also the STS audience)
	SubjectToken       string
	GrantType          string
	RequestedTokenType string
	Scope              string
	SubjectTokenType   string
}

// GCPSTSAPI is the seam over the GCP STS endpoint (https://sts.googleapis.com/v1/token).
type GCPSTSAPI interface {
	ExchangeToken(ctx context.Context, in GCPExchangeInput) (Credentials, error)
}

// BuildGCPExchange constructs and validates the GCP STS request using direct
// resource access (no service-account impersonation).
func BuildGCPExchange(providerResource, token string) (GCPExchangeInput, error) {
	if providerResource == "" {
		return GCPExchangeInput{}, fmt.Errorf("gcp exchange: empty provider resource")
	}
	if token == "" {
		return GCPExchangeInput{}, fmt.Errorf("gcp exchange: empty subject token")
	}
	return GCPExchangeInput{
		Audience:           providerResource,
		SubjectToken:       token,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		Scope:              "https://www.googleapis.com/auth/cloud-platform",
	}, nil
}
