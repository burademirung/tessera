package federation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type capturingDoer struct {
	lastBody string
	resp     string
}

func (d *capturingDoer) Do(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	d.lastBody = string(b)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(d.resp)),
		Header:     make(http.Header),
	}, nil
}

func TestAudienceFor(t *testing.T) {
	auds := Audiences{AWS: "sts.amazonaws.com", GCP: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc", Azure: "api://AzureADTokenExchange"}
	for _, tt := range []struct {
		c    Cloud
		want string
	}{
		{CloudAWS, "sts.amazonaws.com"},
		{CloudGCP, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc"},
		{CloudAzure, "api://AzureADTokenExchange"},
	} {
		got, err := AudienceFor(tt.c, auds)
		if err != nil || got != tt.want {
			t.Fatalf("AudienceFor(%q) = %q,%v want %q", tt.c, got, err, tt.want)
		}
	}
	if _, err := AudienceFor("oracle", auds); err == nil {
		t.Fatal("unknown cloud must error")
	}
}

func TestMintForUsesDistinctCloud(t *testing.T) {
	d := &capturingDoer{resp: `{"token":"header.payload.sig"}`}
	auds := Audiences{AWS: "aws-aud", GCP: "gcp-aud", Azure: "az-aud"}
	m := NewTokenMinter("https://idp.tessera.example/federate", "repo:org/tessera:environment:production", auds, d)

	tok, err := m.MintFor(context.Background(), CloudAWS)
	if err != nil || tok != "header.payload.sig" {
		t.Fatalf("MintFor(aws) = %q,%v", tok, err)
	}
	var sent map[string]string
	if err := json.Unmarshal([]byte(d.lastBody), &sent); err != nil {
		t.Fatalf("body not JSON: %s", d.lastBody)
	}
	if sent["cloud"] != "aws" {
		t.Fatalf("aws cloud = %q, want aws", sent["cloud"])
	}
	if sent["sub"] != "repo:org/tessera:environment:production" {
		t.Fatalf("sub = %q (must be exact, no wildcard)", sent["sub"])
	}

	if _, err := m.MintFor(context.Background(), CloudGCP); err != nil {
		t.Fatalf("MintFor(gcp): %v", err)
	}
	_ = json.Unmarshal([]byte(d.lastBody), &sent)
	if sent["cloud"] != "gcp" {
		t.Fatalf("gcp cloud = %q, want gcp (distinct per cloud)", sent["cloud"])
	}
}
