package federation

import "testing"

func TestBuildGCPExchange(t *testing.T) {
	const provider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov"
	in, err := BuildGCPExchange(provider, "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildGCPExchange: %v", err)
	}
	if in.Audience != provider {
		t.Fatalf("Audience = %q, want provider resource URL", in.Audience)
	}
	if in.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("GrantType = %q", in.GrantType)
	}
	if in.SubjectTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("SubjectTokenType = %q", in.SubjectTokenType)
	}
	if in.RequestedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("RequestedTokenType = %q", in.RequestedTokenType)
	}
	if in.Scope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("Scope = %q", in.Scope)
	}
}

func TestBuildGCPExchangeRejectsEmpty(t *testing.T) {
	if _, err := BuildGCPExchange("", "t"); err == nil {
		t.Fatal("empty provider must error")
	}
	if _, err := BuildGCPExchange("p", ""); err == nil {
		t.Fatal("empty token must error")
	}
}
