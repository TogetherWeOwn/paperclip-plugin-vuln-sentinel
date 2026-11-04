ALTER TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_snapshots
  DROP CONSTRAINT source_snapshots_source_kind_check;
ALTER TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_snapshots
  ADD CONSTRAINT source_snapshots_source_kind_check CHECK (source_kind IN ('lockfiles', 'osv', 'discovery'));
