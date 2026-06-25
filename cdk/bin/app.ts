import { App, Environment, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AccessReviewStack } from '../lib/access-review-stack';

// Pinned env (env-agnostic stacks cannot use fromLookup and weaken cdk-nag).
// Account/region come from the deploy environment; fall back to demo defaults
// so `cdk synth` / Jest work offline.
const env: Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT ?? '123456789012',
  region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
};

export function buildApp(): { app: App; stack: AccessReviewStack } {
  const app = new App();
  const stack = new AccessReviewStack(app, 'LifecycleAccessReview', {
    env,
    tags: { project: 'ident-fed-demo', managed_by: 'cdk' },
  });

  // cdk-nag v3 API: register the plugin on the app (NOT Aspects.of().add()).
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));

  return { app, stack };
}

// Synthesize only when run as the CDK app entrypoint (ts-node bin/app.ts),
// NOT when imported by Jest — otherwise every test triggers a full synth +
// cdk-nag pass on import.
if (require.main === module) {
  buildApp().app.synth();
}
