package federation

import (
	"context"
	"fmt"
	"strings"
)

// AzureExchangeInput is the client-credentials-with-client_assertion request
// shape (brief-03 §3).
type AzureExchangeInput struct {
	TokenURL            string
	ClientID            string
	ClientAssertion     string
	ClientAssertionType string
	GrantType           string
	Scope               string
}

// AzureTokenAPI is the seam over the Entra token endpoint.
type AzureTokenAPI interface {
	Exchange(ctx context.Context, in AzureExchangeInput) (Credentials, error)
}

// BuildAzureExchange constructs and validates the Azure FIC token request.
func BuildAzureExchange(tenant, clientID, assertion string) (AzureExchangeInput, error) {
	if tenant == "" || clientID == "" || assertion == "" {
		return AzureExchangeInput{}, fmt.Errorf("azure exchange: tenant, client id and assertion are required")
	}
	return AzureExchangeInput{
		TokenURL:            "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
		ClientID:            clientID,
		ClientAssertion:     assertion,
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		GrantType:           "client_credentials",
		Scope:               "https://management.azure.com/.default",
	}, nil
}

// IsPropagationError reports whether err is the FIC-not-yet-propagated error.
func IsPropagationError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "AADSTS70021")
}

// ExchangeWithRetry retries only on the FIC propagation delay (AADSTS70021);
// any other error fails fast. backoff is injected so tests do not sleep.
func ExchangeWithRetry(ctx context.Context, api AzureTokenAPI, in AzureExchangeInput, attempts int, backoff func(attempt int)) (Credentials, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		creds, err := api.Exchange(ctx, in)
		if err == nil {
			return creds, nil
		}
		if !IsPropagationError(err) {
			return Credentials{}, err
		}
		lastErr = err
		if attempt < attempts {
			backoff(attempt)
		}
	}
	return Credentials{}, fmt.Errorf("azure exchange exhausted retries (propagation): %w", lastErr)
}
