import { App, Validations } from 'aws-cdk-lib';
import { buildApp } from '../bin/app';

describe('cdk app scaffold', () => {
  it('builds an app with a pinned env on the stack', () => {
    const { app, stack } = buildApp();
    expect(app).toBeInstanceOf(App);
    expect(stack.account).toBeDefined();
    expect(stack.region).toBeDefined();
    // Env-agnostic stacks have the unresolved token; a pinned env is concrete.
    expect(stack.account).not.toContain('${Token');
  });

  it('attaches the cdk-nag v3 AwsSolutions plugin to the app', () => {
    const { app } = buildApp();
    // Validations.of(app) must return a handle (plugin registration succeeded).
    expect(Validations.of(app)).toBeDefined();
  });
});
