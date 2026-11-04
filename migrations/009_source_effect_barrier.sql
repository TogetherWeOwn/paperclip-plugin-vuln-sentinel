ALTER TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_polls
  ADD COLUMN effect_barrier jsonb;
ALTER TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_polls
  ADD COLUMN effect_history jsonb NOT NULL DEFAULT '[]'::jsonb;
