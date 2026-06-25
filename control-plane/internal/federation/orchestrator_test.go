package federation

import (
	"context"
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
)

// capturingDoer is reused from idp_test.go (same package). The orchestrator
// mints via the real TokenMinter, so only the cloud-exchange APIs are stubbed.

type stubAWS struct{ called bool }

func (s *stubAWS) AssumeRoleWithWebIdentity(_ context.Context, _ AWSExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "aws-key"}, nil
}

type stubGCP struct{ called bool }

func (s *stubGCP) ExchangeToken(_ context.Context, _ GCPExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "gcp-key"}, nil
}

type stubAzure struct{ called bool }

func (s *stubAzure) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "az-key"}, nil
}

type nopSink struct{}

func (nopSink) Append(_ context.Context, _ audit.Record) error { return nil }

func TestFederateAll(t *testing.T) {
	d := &capturingDoer{resp: `{"token":"h.p.s"}`}
	m := NewTokenMinter("https://idp.lifecycle.example/federate", "repo:org/r:environment:production",
		Audiences{AWS: "aws-aud", GCP: "gcp-aud", Azure: "az-aud"}, d)
	aws, gcp, az := &stubAWS{}, &stubGCP{}, &stubAzure{}
	o := NewOrchestrator(m, aws, gcp, az, audit.NewChain(nopSink{}))

	creds, err := o.FederateAll(context.Background(), Targets{
		AWSRoleARN: "arn:aws:iam::1:role/r", AWSSessionName: "s",
		GCPProvider: "//iam.googleapis.com/p", AzureTenant: "t", AzureClientID: "c",
	}, time.Now())
	if err != nil {
		t.Fatalf("FederateAll: %v", err)
	}
	if creds[CloudAWS].AccessKeyID != "aws-key" || creds[CloudGCP].AccessKeyID != "gcp-key" || creds[CloudAzure].AccessKeyID != "az-key" {
		t.Fatalf("creds = %#v", creds)
	}
	if !aws.called || !gcp.called || !az.called {
		t.Fatal("every cloud must be exchanged")
	}
}
