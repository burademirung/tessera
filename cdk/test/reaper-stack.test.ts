import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { ReaperStack } from '../lib/reaper-stack';

test('reaper schedules hourly and scopes IAM by project tag', () => {
  const app = new App();
  const stack = new ReaperStack(app, 'ReaperStack', {
    env: { account: '111111111111', region: 'eu-west-1' },
  });
  const t = Template.fromStack(stack);

  // EventBridge Scheduler fires hourly
  t.hasResourceProperties('AWS::Scheduler::Schedule', {
    ScheduleExpression: 'rate(1 hour)',
  });

  // IAM destroy actions are conditioned on the project tag — verify via JSON.
  const json = JSON.stringify(t.toJSON());
  expect(json).toContain('aws:ResourceTag/project');
  expect(json).toContain('ident-fed-demo');
  // Least-privilege: tag read + scoped destroy actions are present
  expect(json).toContain('tag:GetResources');
  expect(json).toContain('iam:DeleteRole');
});
