// Package federation orchestrates per-cloud token mint + exchange. The edge IdP
// issues a DISTINCT RS256 token per cloud (correct aud each), then each cloud
// adapter exchanges it for short-lived credentials. Exact aud + exact sub,
// never wildcards (confused-deputy lesson, research 03).
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Cloud identifies a target cloud.
type Cloud string

const (
	CloudAWS   Cloud = "aws"
	CloudGCP   Cloud = "gcp"
	CloudAzure Cloud = "azure"
)

// Audiences holds the distinct per-cloud audience values.
type Audiences struct {
	AWS   string // sts.amazonaws.com (AWS WIF audience for AssumeRoleWithWebIdentity)
	GCP   string // WIF provider resource URL (//iam.googleapis.com/projects/.../providers/...)
	Azure string // api://AzureADTokenExchange
}

// AudienceFor returns the distinct aud for a cloud.
func AudienceFor(c Cloud, a Audiences) (string, error) {
	switch c {
	case CloudAWS:
		return a.AWS, nil
	case CloudGCP:
		return a.GCP, nil
	case CloudAzure:
		return a.Azure, nil
	default:
		return "", fmt.Errorf("unknown cloud %q", c)
	}
}

// HTTPDoer is the injectable HTTP seam (tests use a fake; prod uses http.Client).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// TokenMinter requests per-cloud RS256 tokens from the edge IdP.
type TokenMinter struct {
	idpURL  string
	subject string // exact sub (e.g. GitHub environment), never wildcard
	auds    Audiences
	doer    HTTPDoer
}

// NewTokenMinter constructs a minter bound to one edge IdP and subject.
func NewTokenMinter(idpURL, subject string, auds Audiences, doer HTTPDoer) *TokenMinter {
	return &TokenMinter{idpURL: idpURL, subject: subject, auds: auds, doer: doer}
}

// MintFor requests the RS256 token whose aud matches the target cloud.
// The edge /federate route authoritatively maps cloud->aud itself (security
// boundary), so the mint body carries the cloud selector, not the audience.
func (m *TokenMinter) MintFor(ctx context.Context, c Cloud) (string, error) {
	// Validate the cloud is known (rejects e.g. "oracle"); the audience itself
	// is resolved server-side by the edge route, not sent on the wire.
	if _, err := AudienceFor(c, m.auds); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"cloud": string(c), "sub": m.subject})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.idpURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.doer.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint token for %s: %w", c, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint token for %s: status %d", c, resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode token for %s: %w", c, err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token for %s", c)
	}
	return out.Token, nil
}
