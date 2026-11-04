CREATE TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.decision_records (
  company_id text NOT NULL,
  origin_id text NOT NULL,
  decision_id text NOT NULL,
  input_sha256 text NOT NULL,
  rules_version text NOT NULL,
  input_bundle jsonb NOT NULL,
  decision_bundle jsonb NOT NULL,
  observed_at timestamptz,
  persisted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (company_id, origin_id, decision_id)
);

CREATE TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.finding_records (
  company_id text NOT NULL,
  origin_id text NOT NULL,
  repo text NOT NULL,
  remediation_unit text NOT NULL,
  alias_group text NOT NULL,
  latest_decision_id text NOT NULL,
  latest_observed_at timestamptz,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (company_id, origin_id)
);
