package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
)

// Targets holds the per-cloud federation targets.
type Targets struct {
	AWSRoleARN     string
	AWSSessionName string
	GCPProvider    string
	AzureTenant    string
	AzureClientID  string
}

// Orchestrator mints a distinct token per cloud and performs each exchange.
type Orchestrator struct {
	minter *TokenMinter
	aws    STSAssumeRoleWebIdentityAPI
	gcp    GCPSTSAPI
	az     AzureTokenAPI
	chain  *audit.Chain
}

// NewOrchestrator wires the minter, the three cloud APIs, and the audit chain.
func NewOrchestrator(m *TokenMinter, aws STSAssumeRoleWebIdentityAPI, gcp GCPSTSAPI, az AzureTokenAPI, ch *audit.Chain) *Orchestrator {
	return &Orchestrator{minter: m, aws: aws, gcp: gcp, az: az, chain: ch}
}

// FederateAll mints + exchanges for all three clouds. One cloud's failure is
// recorded and joined into the returned error but does not abort the others.
func (o *Orchestrator) FederateAll(ctx context.Context, t Targets, now time.Time) (map[Cloud]Credentials, error) {
	out := make(map[Cloud]Credentials, 3)
	var errs []error

	if creds, err := o.federateAWS(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudAWS] = creds
	}
	if creds, err := o.federateGCP(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudGCP] = creds
	}
	if creds, err := o.federateAzure(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudAzure] = creds
	}
	return out, errors.Join(errs...)
}

func (o *Orchestrator) federateAWS(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudAWS)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws mint: %w", err)
	}
	in, err := BuildAWSExchange(t.AWSRoleARN, t.AWSSessionName, tok)
	if err != nil {
		return Credentials{}, err
	}
	creds, err := o.aws.AssumeRoleWithWebIdentity(ctx, in)
	o.emit(ctx, now, CloudAWS, t.AWSRoleARN, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) federateGCP(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudGCP)
	if err != nil {
		return Credentials{}, fmt.Errorf("gcp mint: %w", err)
	}
	in, err := BuildGCPExchange(t.GCPProvider, tok)
	if err != nil {
		return Credentials{}, err
	}
	creds, err := o.gcp.ExchangeToken(ctx, in)
	o.emit(ctx, now, CloudGCP, t.GCPProvider, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("gcp exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) federateAzure(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudAzure)
	if err != nil {
		return Credentials{}, fmt.Errorf("azure mint: %w", err)
	}
	in, err := BuildAzureExchange(t.AzureTenant, t.AzureClientID, tok)
	if err != nil {
		return Credentials{}, err
	}
	// Azure FICs propagate slowly; retry only on AADSTS70021.
	creds, err := ExchangeWithRetry(ctx, o.az, in, 5, func(attempt int) {
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	})
	o.emit(ctx, now, CloudAzure, t.AzureClientID, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("azure exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) emit(ctx context.Context, now time.Time, c Cloud, target string, exchangeErr error) {
	if o.chain == nil {
		return
	}
	outcome := "success"
	if exchangeErr != nil {
		outcome = "failure"
	}
	// Token is never included; only non-secret target metadata.
	_, _ = o.chain.Emit(ctx, audit.Event{
		EventTime: now,
		Actor:     "lifecycle-control-plane",
		Action:    "federation.exchange",
		Subject:   string(c),
		Outcome:   outcome,
		Details:   map[string]string{"cloud": string(c), "target": target},
	})
}
