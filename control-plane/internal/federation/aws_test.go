package federation

import "testing"

func TestBuildAWSExchange(t *testing.T) {
	in, err := BuildAWSExchange("arn:aws:iam::123456789012:role/demo", "lifecycle-demo", "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildAWSExchange: %v", err)
	}
	if in.RoleARN != "arn:aws:iam::123456789012:role/demo" {
		t.Fatalf("RoleARN = %q", in.RoleARN)
	}
	if in.WebIdentityToken != "header.payload.sig" {
		t.Fatalf("WebIdentityToken = %q", in.WebIdentityToken)
	}
	if in.DurationSeconds != 3600 {
		t.Fatalf("DurationSeconds = %d, want 3600 default", in.DurationSeconds)
	}
}

func TestBuildAWSExchangeRejectsEmpty(t *testing.T) {
	for _, tt := range []struct{ arn, sess, tok string }{
		{"", "s", "t"},
		{"arn", "", "t"},
		{"arn", "s", ""},
	} {
		if _, err := BuildAWSExchange(tt.arn, tt.sess, tt.tok); err == nil {
			t.Fatalf("expected error for %+v", tt)
		}
	}
}
