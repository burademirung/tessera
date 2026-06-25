import { Stack, StackProps, Duration } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { CfnSchedule } from 'aws-cdk-lib/aws-scheduler';
import { PolicyStatement, Effect, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';

export class ReaperStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    const fn = new NodejsFunction(this, 'ReaperFn', {
      runtime: Runtime.NODEJS_20_X,
      entry: 'lambda/reaper/index.mjs',
      handler: 'handler',
      timeout: Duration.minutes(5),
    });

    // Least-privilege: tag-read + the specific destroy actions cloud-nuke needs,
    // scoped by a resource-tag condition (project=ident-fed-demo).
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['tag:GetResources'],
        resources: ['*'],
      }),
    );
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'iam:DeleteRole', 'iam:DeleteRolePolicy', 'iam:DetachRolePolicy',
          's3:DeleteBucket', 'dynamodb:DeleteTable',
        ],
        resources: ['*'],
        conditions: {
          StringEquals: { 'aws:ResourceTag/project': 'ident-fed-demo' },
        },
      }),
    );

    // Scheduler execution role — allows EventBridge Scheduler to invoke the Lambda.
    const schedulerRole = new Role(this, 'ReaperSchedulerRole', {
      assumedBy: new ServicePrincipal('scheduler.amazonaws.com'),
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
