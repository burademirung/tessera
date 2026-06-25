import { Stack, StackProps, Duration, Aws } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { CfnSchedule } from 'aws-cdk-lib/aws-scheduler';
import {
  PolicyStatement,
  Effect,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';

export class ReaperStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    const fn = new NodejsFunction(this, 'ReaperFn', {
      runtime: Runtime.NODEJS_20_X,
      entry: 'lambda/reaper/index.mjs',
      handler: 'handler',
      timeout: Duration.minutes(5),
    });

    // Least-privilege IAM for the reaper Lambda execution role:
    //
    // 1. tag:GetResources — Resource:* is mandatory (the Tagging API has no
    //    resource-level ARN scoping); restrict by adding a tag filter in code.
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['tag:GetResources'],
        resources: ['*'],
      }),
    );

    // 2. Destructive actions — scoped to resources tagged project=ident-fed-demo
    //    or project=tessera AND confined to this account (aws:ResourceAccount) to
    //    prevent cross-account escalation.
    //
    //    Finding 3 fix: add aws:ResourceAccount condition alongside the tag
    //    condition to ensure deletes cannot target resources in other accounts,
    //    even if they carry the same tag.
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'iam:DeleteRole', 'iam:DeleteRolePolicy', 'iam:DetachRolePolicy',
          's3:DeleteBucket', 'dynamodb:DeleteTable',
        ],
        resources: ['*'],
        conditions: {
          StringEquals: {
            'aws:ResourceTag/project': ['ident-fed-demo', 'tessera'],
            // Scope to this account only — prevents confused-deputy on resource side.
            'aws:ResourceAccount': Aws.ACCOUNT_ID,
          },
        },
      }),
    );

    // Scheduler execution role — SECURITY FIX (Finding 2):
    // Add aws:SourceArn and aws:SourceAccount conditions to the assume-role
    // trust policy to prevent confused-deputy attacks where a scheduler in
    // another account/region could assume this role.
    //
    // The schedule ARN is built from known parts; Aws.PARTITION / REGION / ACCOUNT_ID
    // are CloudFormation pseudo-parameters resolved at deploy time.
    const scheduleArn = `arn:${Aws.PARTITION}:scheduler:${Aws.REGION}:${Aws.ACCOUNT_ID}:schedule/default/ReaperSchedule`;

    const schedulerRole = new Role(this, 'ReaperSchedulerRole', {
      assumedBy: new ServicePrincipal('scheduler.amazonaws.com', {
        conditions: {
          // Confused-deputy mitigations per AWS IAM guidance:
          // https://docs.aws.amazon.com/scheduler/latest/UserGuide/cross-service-confused-deputy-prevention.html
          ArnLike: { 'aws:SourceArn': scheduleArn },
          StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID },
        },
      }),
    });
    fn.grantInvoke(schedulerRole);

    // L1 CfnSchedule — stable in aws-cdk-lib 2.x (no alpha package needed).
    new CfnSchedule(this, 'ReaperSchedule', {
      scheduleExpression: 'rate(1 hour)',
      flexibleTimeWindow: { mode: 'OFF' },
      description: 'Hourly tag-scoped TTL reaper (independent of GitHub scheduler)',
      target: {
        arn: fn.functionArn,
        roleArn: schedulerRole.roleArn,
      },
    });
  }
}
