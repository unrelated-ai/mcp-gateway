-- migrate:up
ALTER TABLE profiles ADD COLUMN revision bigint NOT NULL DEFAULT 1;

-- Advance on every profile update, including unconditional administrative writes.
-- Association detachments update the parent row in the same transaction.
CREATE FUNCTION bump_profile_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.revision := OLD.revision + 1;
  RETURN NEW;
END;
$$;
CREATE TRIGGER profiles_revision BEFORE UPDATE ON profiles
FOR EACH ROW EXECUTE FUNCTION bump_profile_revision();

-- migrate:down
DROP TRIGGER profiles_revision ON profiles;
DROP FUNCTION bump_profile_revision();
ALTER TABLE profiles DROP COLUMN revision;
