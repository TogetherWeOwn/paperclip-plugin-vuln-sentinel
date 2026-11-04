CREATE TABLE plugin_togetherweown_vuln_sentinel_4497ac2b8e.source_polls (
  company_id text NOT NULL,
  repo text NOT NULL,
  revision integer NOT NULL DEFAULT 0,
  bundle jsonb NOT NULL,
  PRIMARY KEY (company_id, repo)
);
