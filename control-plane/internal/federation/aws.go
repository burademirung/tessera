package federation

import (
	"context"
	"fmt"
	"time"
)

// Credentials are short-lived cloud credentials returned by an exchange.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiry          time.Time
}

// AWSExchangeInput is the AssumeRoleWithWebIdentity request shape (brief-03 §1).
type AWSExchangeInput struct {
	RoleARN          string
	RoleSessionName  string
	WebIdentityToken string
	DurationSeconds  int32
}

// STSAssumeRoleWebIdentityAPI is the seam over aws-sdk-go-v2 STS. The real
// adapter calls sts.Client.AssumeRoleWithWebIdentity; unit tests use a fake.
type STSAssumeRoleWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context, in AWSExchangeInput) (Credentials, error)
}

// BuildAWSExchange constructs and validates the STS request. Default duration
// is 1h (within the STS 15m–12h range).
func BuildAWSExchange(roleARN, sessionName, token string) (AWSExchangeInput, error) {
	if roleARN == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty role ARN")
	}
	if sessionName == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty role session name")
	}
	if token == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty web identity token")
	}
	return AWSExchangeInput{
		RoleARN:          roleARN,
		RoleSessionName:  sessionName,
		WebIdentityToken: token,
		DurationSeconds:  3600,
	}, nil
}
