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
