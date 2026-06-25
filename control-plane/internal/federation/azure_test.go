package federation

import (
	"context"
	"errors"
	"testing"
)

func TestBuildAzureExchange(t *testing.T) {
	in, err := BuildAzureExchange("tenant-guid", "client-guid", "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildAzureExchange: %v", err)
	}
	if in.TokenURL != "https://login.microsoftonline.com/tenant-guid/oauth2/v2.0/token" {
		t.Fatalf("TokenURL = %q", in.TokenURL)
	}
	if in.GrantType != "client_credentials" {
		t.Fatalf("GrantType = %q", in.GrantType)
	}
	if in.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("ClientAssertionType = %q", in.ClientAssertionType)
	}
	if in.Scope != "https://management.azure.com/.default" {
		t.Fatalf("Scope = %q", in.Scope)
	}
}

type flakyAzure struct {
	failTimes int
	calls     int
}

func (f *flakyAzure) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	f.calls++
	if f.calls <= f.failTimes {
		return Credentials{}, errors.New("AADSTS70021: No matching federated identity record found")
	}
	return Credentials{AccessKeyID: "ok"}, nil
}

func TestExchangeWithRetryOnPropagation(t *testing.T) {
	api := &flakyAzure{failTimes: 2}
	in, _ := BuildAzureExchange("t", "c", "tok")
	got, err := ExchangeWithRetry(context.Background(), api, in, 5, func(int) {})
	if err != nil {
		t.Fatalf("retry should succeed after propagation: %v", err)
	}
	if got.AccessKeyID != "ok" || api.calls != 3 {
		t.Fatalf("calls = %d, creds = %#v", api.calls, got)
	}
}

func TestExchangeWithRetryFailsFastOnOtherError(t *testing.T) {
	// Pointer receiver so calls is observable to the test (a value receiver would
	// count on a copy and always report 0 — the classic fake-receiver bug).
	api := &failAlways{err: errors.New("AADSTS7000215: invalid client secret")}
	in, _ := BuildAzureExchange("t", "c", "tok")
	if _, err := ExchangeWithRetry(context.Background(), api, in, 5, func(int) {}); err == nil {
		t.Fatal("non-propagation error must not be retried")
	}
	if api.calls != 1 {
		t.Fatalf("calls = %d, want 1 (fail fast)", api.calls)
	}
}

type failAlways struct {
	err   error
	calls int
}

func (f *failAlways) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	f.calls++
	return Credentials{}, f.err
}
