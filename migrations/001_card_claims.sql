CREATE TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.card_claims (
  company_id text NOT NULL,
  origin_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('reserved', 'creating', 'linked', 'refreshing', 'indeterminate', 'quarantined')),
  claim_token text NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now(),
  issue_id text,
  advisory_modified text,
  attempt_count integer NOT NULL DEFAULT 0,
  last_error text,
  recovery_audit jsonb,
  PRIMARY KEY (company_id, origin_id)
);
