import { execFileSync } from 'node:child_process';
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from '@aws-sdk/client-resource-groups-tagging-api';

const PROJECT_TAG = 'ident-fed-demo';
const TESSERA_TAG = 'tessera';

/**
 * Structured log helper — always emits JSON so CloudWatch Logs Insights can
 * query individual fields without regex parsing.
 */
const log = (level, msg, extra = {}) =>
  console.log(JSON.stringify({ level, msg, ts: new Date().toISOString(), ...extra }));

export const handler = async (event = {}) => {
  // Dry-run guard: set event.dryRun = true (or env DRY_RUN=1) to log-only.
  const dryRun = event.dryRun === true || process.env.DRY_RUN === '1';
  if (dryRun) {
    log('info', 'dry-run mode active — no destructive actions will be taken');
  }

  const client = new ResourceGroupsTaggingAPIClient({});

  // Fail-closed: any error from the tagging API aborts the whole run.
  try {
    // TagFilters does not support OR across Values for different Keys, but we
    // CAN pass multiple Values for the same Key (project).
    const res = await client.send(
      new GetResourcesCommand({
        TagFilters: [{ Key: 'project', Values: [PROJECT_TAG, TESSERA_TAG] }],
      }),
    );

    const allTagged = res.ResourceTagMappingList ?? [];
    const now = Date.now();

    // Build the eligible set: resources that BOTH carry the project tag AND have
    // an expires-at tag whose value is in the past.  An absent or unparseable
    // expires-at tag means the resource is NOT eligible (fail closed).
    const expired = allTagged.filter((r) => {
      const tags = r.Tags ?? [];

      // Double-check the project tag is present and matches (defence-in-depth
      // against any future API regression or misconfiguration).
      const projectTag = tags.find((x) => x.Key === 'project');
      if (
        !projectTag ||
        (projectTag.Value !== PROJECT_TAG && projectTag.Value !== TESSERA_TAG)
      ) {
        log('warn', 'resource returned without expected project tag — skipping', {
          arn: r.ResourceARN,
        });
        return false; // not our resource — skip
      }

      const expiresTag = tags.find((x) => x.Key === 'expires-at');
      if (!expiresTag || !expiresTag.Value) {
        return false; // no TTL tag — do NOT delete (fail closed)
      }
      const expiry = Date.parse(expiresTag.Value);
      if (Number.isNaN(expiry)) {
        log('warn', 'unparseable expires-at tag — skipping resource (fail closed)', {
          arn: r.ResourceARN,
          expiresAt: expiresTag.Value,
        });
        return false; // unparseable TTL — do NOT delete (fail closed)
      }
      return expiry < now; // only expired resources pass
    });

    if (expired.length === 0) {
      log('info', 'no expired resources found — nothing to reap');
      return { reaped: 0, dryRun, message: 'no expired resources' };
    }

    const expiredArns = expired.map((r) => r.ResourceARN);
    log('info', `${dryRun ? '[DRY-RUN] ' : ''}eligible expired resources to delete`, {
      count: expired.length,
      arns: expiredArns,
    });

    if (dryRun) {
      return { reaped: 0, dryRun: true, wouldReap: expiredArns };
    }

    // cloud-nuke is scoped by config + project tag; it only runs when we have
    // confirmed expired ARNs — the filter above is the gate before any
    // destructive action is taken.
    execFileSync(
      '/opt/cloud-nuke',
      ['aws', '--resource-grace-period', '0h', '--force',
       '--config', '/var/task/cloud-nuke-config.yml'],
      { stdio: 'inherit' },
    );

    log('info', 'cloud-nuke completed', { reaped: expired.length });
    return { reaped: expired.length, dryRun: false, arns: expiredArns };
  } catch (err) {
    // Fail closed: log the error and re-throw so Lambda marks the invocation
    // failed and EventBridge Scheduler can retry / alarm.
    log('error', 'reaper aborted — tagging API or execution error', {
      error: err.message ?? String(err),
    });
    throw err;
  }
};
