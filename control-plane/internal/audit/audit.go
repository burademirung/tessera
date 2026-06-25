// Package audit emits append-only, hash-chained audit records to an injected
// sink (the edge-API-backed R2 writer). It never logs tokens/credentials:
// secret-bearing detail keys are redacted before hashing and writing.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Record is one immutable audit-log entry (AU-3 six elements + chain fields).
type Record struct {
	Seq        uint64            `json:"seq"`
	EventTime  time.Time         `json:"event_time"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Subject    string            `json:"subject"`
	Outcome    string            `json:"outcome"`
	Details    map[string]string `json:"details"`
	PrevHash   string            `json:"prev_hash"`
	RecordHash string            `json:"record_hash"`
}

// Event is the caller-supplied payload before sequencing/hashing.
type Event struct {
	EventTime time.Time
	Actor     string
	Action    string
	Subject   string
	Outcome   string
	Details   map[string]string
}

// Sink persists records in append-only order (R2 via the edge API).
type Sink interface {
	Append(ctx context.Context, r Record) error
}

// secretKeys are detail keys whose values are redacted before write.
var secretKeys = map[string]bool{
	"token":            true,
	"access_token":     true,
	"refresh_token":    true,
	"id_token":         true,
	"client_secret":    true,
	"client_assertion": true,
	"password":         true,
	"authorization":    true,
	"private_key":      true,
}

// Chain sequences and hash-chains records into a Sink.
type Chain struct {
	sink     Sink
	nextSeq  uint64
	prevHash string
}

// NewChain starts a fresh chain (genesis Seq=1, empty PrevHash).
func NewChain(s Sink) *Chain {
	return &Chain{sink: s, nextSeq: 1}
}

// Emit redacts, sequences, hash-chains, and appends one record. On sink
// failure the sequence/prev-hash are not advanced so a retry is idempotent.
func (c *Chain) Emit(ctx context.Context, ev Event) (Record, error) {
	r := Record{
		Seq:       c.nextSeq,
		EventTime: ev.EventTime.UTC(),
		Actor:     ev.Actor,
		Action:    ev.Action,
		Subject:   ev.Subject,
		Outcome:   ev.Outcome,
		Details:   redact(ev.Details),
		PrevHash:  c.prevHash,
	}
	r.RecordHash = ComputeHash(r)
	if err := c.sink.Append(ctx, r); err != nil {
		return Record{}, fmt.Errorf("audit append seq %d: %w", r.Seq, err)
	}
	c.nextSeq++
	c.prevHash = r.RecordHash
	return r, nil
}

// redact copies details, masking secret-bearing keys.
func redact(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if secretKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

// ComputeHash is SHA-256 over a deterministic encoding of all fields except
// RecordHash itself.
func ComputeHash(r Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n%s\n%s\n%s\n%s\n%s\n%s\n",
		r.Seq, r.EventTime.Format(time.RFC3339Nano),
		r.Actor, r.Action, r.Subject, r.Outcome, r.PrevHash)
	keys := make([]string, 0, len(r.Details))
	for k := range r.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, r.Details[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
