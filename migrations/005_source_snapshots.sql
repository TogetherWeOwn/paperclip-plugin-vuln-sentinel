CREATE TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_snapshots (
  company_id text NOT NULL,
  snapshot_id text NOT NULL,
  source_kind text NOT NULL CHECK (source_kind IN ('lockfiles', 'osv')),
  repo text NOT NULL,
  source_sha text NOT NULL,
  bundle jsonb NOT NULL,
  persisted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (company_id, snapshot_id)
);
