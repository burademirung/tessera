# cdk — AWS CDK Access-Review Pipeline

The `cdk` package defines a single AWS CDK stack (`AccessReviewStack`) that provisions the AWS infrastructure for Tessera's periodic access-certification campaigns. The pipeline wires EventBridge (scheduler) → Step Functions (orchestration) → DynamoDB (review record store) with CloudWatch logging and X-Ray tracing enabled throughout.

This stack is deliberately ephemeral: all resources carry `RemovalPolicy.DESTROY` so a `cdk destroy` leaves no orphaned state. It is the CDK half of a clear ownership boundary — DynamoDB and the Step Functions execution IAM role are owned here; the actual review logic and entitlement data are owned by the Go control-plane.

---

## Role in the system

```
EventBridge Rule (every 30 days)
       │
       ▼
Step Functions Standard State Machine
       │
       ▼
DynamoDB PutItem (reviewId, entitlementId, status="pending")
       │
       ▼  (consumed by)
Go control-plane access-review command
```

The CDK stack creates the AWS plumbing. The `cmd/access-review` binary in the Go control-plane reads from and writes to DynamoDB to drive the certification workflow.

---

## Stack: `AccessReviewStack`

**Source**: `lib/access-review-stack.ts`

**Entry point**: `bin/app.ts` (instantiates the stack with `env: { account, region }`).

### Resources created

| Resource | CDK construct | Key configuration |
|---|---|---|
| `ReviewTable` | `aws-dynamodb.Table` | PK: `reviewId` (STRING), SK: `entitlementId` (STRING). `PAY_PER_REQUEST` billing. `AWS_MANAGED` encryption. Point-in-time recovery enabled. `RemovalPolicy.DESTROY`. |
| `RecordReview` | `aws-stepfunctions-tasks.DynamoPutItem` | Writes `{reviewId, entitlementId, status="pending"}` from execution input via `JsonPath.stringAt('$.reviewId')` / `JsonPath.stringAt('$.entitlementId')`. |
| `ReviewSfnLogs` | `aws-logs.LogGroup` | `RetentionDays.ONE_WEEK`. `RemovalPolicy.DESTROY`. |
| `AccessReviewStateMachine` | `aws-stepfunctions.StateMachine` | `STANDARD` type. 5-minute timeout. X-Ray tracing enabled. `LogLevel.ALL` with execution data. |
| `AccessReviewSchedule` | `aws-events.Rule` | `Schedule.rate(Duration.days(30))` targeting the state machine. |

### IAM

The L2 `StateMachine` construct auto-generates an execution role. This role receives a `Resource::*` IAM5 finding from cdk-nag v3 (wildcard on sub-resources of the table and log group ARNs). The finding is acknowledged with `Validations.of(stateMachine).acknowledge(...)` at the exact `RuleId[FindingId]` required by cdk-nag v3.

Point-in-time recovery is enabled on the table, so the `AwsSolutions-DDB3` cdk-nag finding does not fire (no acknowledgement needed).

---

## cdk-nag v3

The stack uses **cdk-nag v3** for security best-practice validation at synth time.

Key v3 behavioural difference from v2: there is no bulk suppression API. Each finding must be acknowledged individually by its exact `RuleId[FindingId]` string (e.g. `AwsSolutions-IAM5[Resource::*]`). The bracketed FindingId must be copied verbatim from the `cdk synth` error output if it changes.

The `Validations.of(construct).acknowledge({id, reason})` call in `access-review-stack.ts` is the only suppression in the stack.

---

## RemovalPolicy.DESTROY

Both the `ReviewTable` and `ReviewSfnLogs` log group use `RemovalPolicy.DESTROY`. This is intentional: the access-review infrastructure is ephemeral and should not leave orphaned resources after a `cdk destroy`. Review records are considered transient state (the source of truth for entitlements lives in the Go control-plane and the edge D1 store).

---

## Build and test

### Prerequisites

- Node.js ≥ 20 (LTS)
- `npm ci` (installs pinned dependencies from `package-lock.json`)

### Install dependencies

```sh
npm ci
```

### Compile TypeScript

```sh
npm run build
# equivalent to: tsc
```

### Run unit tests (Jest)

```sh
npm test
# equivalent to: jest
```

Tests are in `test/access-review-stack.test.ts` and `test/app.test.ts`. They synthesize the stack against a mock account/region and assert on the generated CloudFormation template using `aws-cdk-lib/assertions`.

Test coverage:
- DynamoDB table is `PAY_PER_REQUEST`.
- Table `DeletionPolicy: Delete` and `UpdateReplacePolicy: Delete` (RemovalPolicy.DESTROY).
- Exactly one Step Functions state machine.
- Exactly one EventBridge rule with `rate(30 days)` schedule expression.
- Snapshot test of the full synthesized template (`__snapshots__/access-review-stack.test.ts.snap`).

### Synthesize CloudFormation

```sh
npx cdk synth
# or via npm script:
npm run synth
```

This runs cdk-nag at synth time. Any unacknowledged findings cause synthesis to fail.

### Diff against deployed stack

```sh
npm run diff
```

---

## Configuration

The CDK stack does not read environment variables or external configuration files. All parameters are hardcoded in the stack constructor (schedule cadence, table keys, retention period). To change the review cadence, edit `Schedule.rate(Duration.days(30))` in `lib/access-review-stack.ts` and re-synth.

The `env` (AWS account and region) is set in `bin/app.ts`. For CI deployment, pass `-c` context overrides or set `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`.

---

## Terraform / CDK ownership boundary

The access-review infrastructure is intentionally split across two IaC tools:

| Concern | Owner |
|---|---|
| Multi-cloud federation trust (OIDC providers, WIF pools, Azure FICs, IAM roles) | `terraform/` |
| AWS access-review pipeline (EventBridge, Step Functions, DynamoDB) | `cdk/` (this package) |

The boundary exists because the federation trust is multi-cloud and benefits from Terraform's provider ecosystem, while the access-review pipeline is AWS-only and benefits from CDK's L2 construct abstractions and cdk-nag policy-as-code. The two stacks do not share state or outputs.

---

## Dependencies

| Package | Purpose |
|---|---|
| `aws-cdk-lib ^2.257.0` | All L2 CDK constructs |
| `cdk-nag ^3.0.1` | Security best-practice validation at synth |
| `constructs ^10.5.1` | CDK construct base |
| `jest ^29.7.0` | Test runner |
| `ts-jest ^29.2.0` | TypeScript Jest transformer |
| `typescript ^5.5.0` | TypeScript compiler |

---

## Connections to other subsystems

| Direction | Counterpart | What crosses the boundary |
|---|---|---|
| Outbound (data) | `control-plane/` | The `ReviewTable` DynamoDB table is read and written by `cmd/access-review`. The EventBridge rule triggers the Go control-plane's review campaign logic. |
| Boundary | `terraform/` | Terraform owns all federation trust resources; CDK owns only the access-review pipeline. No shared state or cross-stack references. |
