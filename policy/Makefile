.PHONY: fmt fmt-check check lint test cover all

# NOTE: OPA 1.17 defaults to Rego v1; the legacy `--rego-v1` flag is now `--v0-v1`
# and expects v0 input, so it rejects our pure-v1 sources. Plain `opa fmt` formats
# as v1 (the default), which is what we want.
fmt:
	opa fmt -w .

fmt-check:
	opa fmt --diff --fail .

check:
	opa check --strict --v1-compatible .

lint:
	regal lint .

# Explicit dirs (not `.`) so opa never tries to load coverage.json as data.
test:
	opa test authz conformance -v

cover:
	opa test authz conformance --coverage --format=json --fail-on-empty > coverage.json
	@opa test authz conformance --coverage --format=json | python3 -c "import sys,json; c=json.load(sys.stdin); cov=c.get('coverage',0); print(f'coverage: {cov:.1f}%'); sys.exit(0 if cov>=90 else 1)"

all: fmt-check check lint cover

.PHONY: iac-verify iac-test iac-bundle

# Unit-test the guardrails (fixtures wrapped as data.plan_{good,bad}).
iac-verify:
	conftest verify --policy iac --data iac/fixtures

# Gate a real plan: the good plan must be clean; the bad plan is expected to
# report violations (|| true so the demo run does not abort the target).
iac-test:
	conftest test iac/plans/plan_bad.json --policy iac --namespace iac --no-color || true
	conftest test iac/plans/plan_good.json --policy iac --namespace iac

# Real OPA SIGNED bundle for the IaC side (distinct from the self-signed runtime
# bundle). Requires an Ed25519/RSA signing key at signing.pem (CI/operator-supplied).
iac-bundle:
	opa build -b iac --signing-key signing.pem -o iac-bundle.tar.gz
	@echo "real OPA signed bundle: iac-bundle.tar.gz (IaC side only)"
