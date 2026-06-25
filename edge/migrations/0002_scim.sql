-- SCIM Users/Groups, tenant-scoped. externalId<->id correlation persisted.
CREATE TABLE IF NOT EXISTS scim_users (
  tenant       TEXT NOT NULL,
  id           TEXT NOT NULL,
  user_name    TEXT NOT NULL,
  external_id  TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  display_name TEXT,
  body         TEXT NOT NULL,           -- full canonical JSON
  version      INTEGER NOT NULL DEFAULT 1,
  created      TEXT NOT NULL,
  last_modified TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_users_username ON scim_users(tenant, user_name);
CREATE INDEX IF NOT EXISTS ix_scim_users_externalid ON scim_users(tenant, external_id);

CREATE TABLE IF NOT EXISTS scim_groups (
  tenant       TEXT NOT NULL,
  id           TEXT NOT NULL,
  display_name TEXT NOT NULL,
  external_id  TEXT,
  body         TEXT NOT NULL,
  version      INTEGER NOT NULL DEFAULT 1,
  created      TEXT NOT NULL,
  last_modified TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_groups_displayname ON scim_groups(tenant, display_name);
