package audit

import (
	"context"
	"testing"
	"time"
)

type fakeSink struct {
	records []Record
	failOn  uint64 // fail Append when r.Seq == failOn (0 = never)
}

func (f *fakeSink) Append(_ context.Context, r Record) error {
	if r.Seq == f.failOn {
		return errFail
	}
	f.records = append(f.records, r)
	return nil
}

var errFail = &appendErr{}

type appendErr struct{}

func (*appendErr) Error() string { return "append failed" }

func ev(action, subject string, details map[string]string) Event {
	return Event{
		EventTime: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC),
		Actor:     "tessera-control-plane",
		Action:    action,
		Subject:   subject,
		Outcome:   "success",
		Details:   details,
	}
}

func TestEmitChainsHashes(t *testing.T) {
	s := &fakeSink{}
	c := NewChain(s)
	r1, err := c.Emit(context.Background(), ev("leaver.start", "u1", nil))
	if err != nil {
		t.Fatalf("emit1: %v", err)
	}
	r2, err := c.Emit(context.Background(), ev("leaver.done", "u1", nil))
	if err != nil {
		t.Fatalf("emit2: %v", err)
	}
	if r1.Seq != 1 || r2.Seq != 2 {
		t.Fatalf("seq = %d,%d want 1,2", r1.Seq, r2.Seq)
	}
	if r1.PrevHash != "" {
		t.Fatalf("genesis PrevHash must be empty, got %q", r1.PrevHash)
	}
	if r2.PrevHash != r1.RecordHash {
		t.Fatalf("chain broken: r2.PrevHash %q != r1.RecordHash %q", r2.PrevHash, r1.RecordHash)
	}
	if r1.RecordHash == "" || r1.RecordHash == r2.RecordHash {
		t.Fatalf("record hashes must be present and distinct")
	}
}

func TestEmitRedactsSecretsBeforeWrite(t *testing.T) {
	s := &fakeSink{}
	c := NewChain(s)
	_, err := c.Emit(context.Background(), ev("federation.exchange", "aws", map[string]string{
		"role":          "demo",
		"access_token":  "ya29.SECRET",
		"client_secret": "shhh",
	}))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	got := s.records[0].Details
	if got["access_token"] != "[REDACTED]" || got["client_secret"] != "[REDACTED]" {
		t.Fatalf("secrets not redacted: %#v", got)
	}
	if got["role"] != "demo" {
		t.Fatalf("non-secret detail was altered: %#v", got)
	}
}

func TestEmitDoesNotAdvanceOnSinkFailure(t *testing.T) {
	s := &fakeSink{failOn: 2}
	c := NewChain(s)
	r1, err := c.Emit(context.Background(), ev("a", "u1", nil))
	if err != nil {
		t.Fatalf("emit1: %v", err)
	}
	if _, err := c.Emit(context.Background(), ev("b", "u1", nil)); err == nil {
		t.Fatal("expected sink failure to propagate")
	}
	// Clear the injected failure and retry: the chain must reuse seq 2 and chain
	// off record 1 (a failed Append must not advance seq/prev-hash).
	s.failOn = 0
	r2, err := c.Emit(context.Background(), ev("b-retry", "u1", nil))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if r2.Seq != 2 {
		t.Fatalf("retry seq = %d, want 2 (failure must not advance)", r2.Seq)
	}
	if r2.PrevHash != r1.RecordHash {
		t.Fatalf("retry must chain off record 1: PrevHash %q != %q", r2.PrevHash, r1.RecordHash)
	}
}
