alter table scans
  add column risk_score integer;

-- Backfill: existing rows get NULL, which is fine — UI handles missing.
