import { execFileSync } from 'node:child_process';
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from '@aws-sdk/client-resource-groups-tagging-api';

const PROJECT_TAG = 'ident-fed-demo';

export const handler = async () => {
  const client = new ResourceGroupsTaggingAPIClient({});
  const res = await client.send(
    new GetResourcesCommand({
      TagFilters: [{ Key: 'project', Values: [PROJECT_TAG] }],
    }),
  );
  const now = Date.now();
  const expired = (res.ResourceTagMappingList ?? []).filter((r) => {
    const t = (r.Tags ?? []).find((x) => x.Key === 'expires-at');
    return t && Date.parse(t.Value) < now;
  });
  if (expired.length === 0) {
    return { reaped: 0, message: 'no expired resources' };
  }
  // cloud-nuke scoped to the project tag; --force for non-interactive.
  execFileSync(
    '/opt/cloud-nuke',
    ['aws', '--resource-grace-period', '0h', '--force',
     '--config', '/var/task/cloud-nuke-config.yml'],
    { stdio: 'inherit' },
  );
  return { reaped: expired.length };
};
