-- Minimal schema for the OpenEMR transfer case (GHSA-q366-cv5v-83w8).
-- admin.php's vulnerable/patched read path only needs these two tables,
-- not OpenEMR's full multi-hundred-table schema (see docs/OPENEMR_TRANSFER_CASE_PLAN.md
-- for why: this is the same minimal-dependency-scoping principle already
-- applied to the free5GC runtime harness).

CREATE TABLE IF NOT EXISTS globals (
  gl_name VARCHAR(255) NOT NULL,
  gl_index INT NOT NULL DEFAULT 0,
  gl_value TEXT,
  PRIMARY KEY (gl_name, gl_index)
);

INSERT INTO globals (gl_name, gl_index, gl_value)
VALUES ('openemr_name', 0, 'Transfer Case Test Clinic (fake local test data)');

CREATE TABLE IF NOT EXISTS version (
  v_major INT,
  v_minor INT,
  v_patch INT,
  v_tag VARCHAR(40),
  v_realpatch VARCHAR(40),
  v_database INT,
  v_acl INT
);

-- v_database/v_acl match version.php's own $v_database/$v_acl constants
-- at these commits, so the rendered page's "Is Current" column is
-- accurate rather than an artifact of an incomplete seed.
INSERT INTO version (v_major, v_minor, v_patch, v_tag, v_realpatch, v_database, v_acl)
VALUES (8, 3, 0, '-dev', '0', 541, 13);
