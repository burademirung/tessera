import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AccessReviewStack } from '../lib/access-review-stack';

function synth(): Template {
  const app = new App();
  const stack = new AccessReviewStack(app, 'TestAccessReview', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

describe('AccessReviewStack', () => {
  it('creates a PAY_PER_REQUEST DynamoDB table', () => {
    const t = synth();
    t.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
    });
  });

  it('sets RemovalPolicy.DESTROY on the table (ephemeral)', () => {
    const t = synth();
    t.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Delete',
      UpdateReplacePolicy: 'Delete',
    });
  });

  it('creates a Step Functions state machine', () => {
    const t = synth();
    t.resourceCountIs('AWS::StepFunctions::StateMachine', 1);
  });

  it('creates an EventBridge rule targeting the state machine', () => {
    const t = synth();
    t.resourceCountIs('AWS::Events::Rule', 1);
    t.hasResourceProperties('AWS::Events::Rule', {
      ScheduleExpression: 'rate(30 days)',
    });
  });

  it('matches the synthesized template snapshot', () => {
    expect(synth().toJSON()).toMatchSnapshot();
  });
});
