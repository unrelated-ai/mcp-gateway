-- migrate:up
CREATE SEQUENCE tool_source_revision_seq;
ALTER TABLE tool_sources ADD COLUMN revision bigint NOT NULL DEFAULT nextval('tool_source_revision_seq');
ALTER SEQUENCE tool_source_revision_seq OWNED BY tool_sources.revision;

CREATE FUNCTION bump_tool_source_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.revision := nextval('tool_source_revision_seq');
  RETURN NEW;
END;
$$;
CREATE TRIGGER tool_sources_revision BEFORE UPDATE ON tool_sources
FOR EACH ROW EXECUTE FUNCTION bump_tool_source_revision();

-- migrate:down
DROP TRIGGER tool_sources_revision ON tool_sources;
DROP FUNCTION bump_tool_source_revision();
ALTER TABLE tool_sources DROP COLUMN revision;
