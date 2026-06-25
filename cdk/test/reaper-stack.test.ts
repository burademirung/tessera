import { App } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { ReaperStack } from '../lib/reaper-stack';

const ACCOUNT = '111111111111';
const REGION = 'eu-west-1';

function buildStack() {
  const app = new App();
  const stack = new ReaperStack(app, 'ReaperStack', {
    env: { account: ACCOUNT, region: REGION },
  });
  return Template.fromStack(stack);
}

describe('ReaperStack – schedule + basic IAM', () => {
  test('EventBridge Scheduler fires hourly', () => {
    const t = buildStack();
    t.hasResourceProperties('AWS::Scheduler::Schedule', {
      ScheduleExpression: 'rate(1 hour)',
    });
  });

  test('IAM destroy actions are conditioned on the project tag', () => {
    const json = JSON.stringify(buildStack().toJSON());
    expect(json).toContain('aws:ResourceTag/project');
    expect(json).toContain('ident-fed-demo');
    // Least-privilege: tag read + scoped destroy actions are present
    expect(json).toContain('tag:GetResources');
    expect(json).toContain('iam:DeleteRole');
  });
});

// ---------------------------------------------------------------------------
// Security: Finding 2 — confused-deputy conditions on the scheduler role
// ---------------------------------------------------------------------------
describe('ReaperStack – confused-deputy mitigations (Finding 2)', () => {
  test('scheduler role assume-role policy contains aws:SourceArn condition', () => {
    const t = buildStack();
    // The scheduler role's AssumeRolePolicyDocument must carry ArnLike on
    // aws:SourceArn so only the specific schedule in this account can assume it.
    t.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: Match.objectLike({
              Service: 'scheduler.amazonaws.com',
            }),
            Condition: Match.objectLike({
              ArnLike: Match.objectLike({
                'aws:SourceArn': Match.anyValue(),
              }),
            }),
          }),
        ]),
      }),
    });
  });

  test('scheduler role assume-role policy contains aws:SourceAccount condition', () => {
    const t = buildStack();
    t.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: Match.objectLike({
              Service: 'scheduler.amazonaws.com',
            }),
            Condition: Match.objectLike({
              StringEquals: Match.objectLike({
                'aws:SourceAccount': { Ref: 'AWS::AccountId' },
              }),
            }),
          }),
        ]),
      }),
    });
  });

  test('scheduler role SourceArn includes the schedule name and account', () => {
    const json = JSON.stringify(buildStack().toJSON());
    // SourceArn should reference ReaperSchedule in the ARN
    expect(json).toContain('ReaperSchedule');
    // SourceAccount should resolve to { Ref: 'AWS::AccountId' }
    expect(json).toContain('AWS::AccountId');
  });
});

// ---------------------------------------------------------------------------
// Security: Finding 3 — scoped IAM with aws:ResourceAccount condition
// ---------------------------------------------------------------------------
describe('ReaperStack – least-privilege IAM scoping (Finding 3)', () => {
  test('destructive actions are conditioned on aws:ResourceAccount', () => {
    const t = buildStack();
    // The policy statement for destructive actions must include aws:ResourceAccount
    // to prevent cross-account resource deletion.
    const json = JSON.stringify(t.toJSON());
    expect(json).toContain('aws:ResourceAccount');
  });

  test('delete policy accepts both project tag values', () => {
    const json = JSON.stringify(buildStack().toJSON());
    // Both tag values must appear in the policy condition.
    expect(json).toContain('ident-fed-demo');
    expect(json).toContain('tessera');
  });

  test('delete policy statement contains aws:ResourceAccount set to this account', () => {
    const t = buildStack();
    // Find a policy that includes s3:DeleteBucket and check it has ResourceAccount.
    t.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith(['s3:DeleteBucket']),
            Condition: Match.objectLike({
              StringEquals: Match.objectLike({
                'aws:ResourceAccount': { Ref: 'AWS::AccountId' },
              }),
            }),
          }),
        ]),
      }),
    });
  });
});
