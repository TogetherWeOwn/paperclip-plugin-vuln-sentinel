ALTER TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.card_claims
  ADD COLUMN origin_kind text NOT NULL DEFAULT 'plugin:togetherweown.vuln-sentinel:finding',
  ADD COLUMN published_revision integer CHECK (published_revision > 0),
  ADD COLUMN published_sha256 text;
